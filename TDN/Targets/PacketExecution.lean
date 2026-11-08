import TDN.Semantics.FiniteExecution
import TDN.Semantics.ExecutionEvents
import TDN.Semantics.ExecutionFragments

namespace TDN.Targets

def RedPayloadOrigin (env : Execution.Environment) (redSourceIfaces : List Nat)
    (initialState : Execution.State) : Prop :=
  initialState.iface ∈ redSourceIfaces ∧ initialState.datapathStage = .localOutput ∧
  initialState.frame.enteredIface = initialState.iface ∧ initialState.frame.envelopes = [] ∧
  initialState.frame.packet.ingress = env.interfaceName initialState.iface ∧ initialState.authenticated = []

def msc_protected_red_payload_stack (env : Execution.Environment)
    (redSourceIfaces blackIfaces : List Nat) : Prop :=
  ∀ initialState finalState actions, RedPayloadOrigin env redSourceIfaces initialState →
    (Execution.lts env).MTr initialState actions finalState → finalState.datapathStage = .ready →
    finalState.iface ∈ blackIfaces → finalState.frame.tags = [2, 1]

lemma red_origin_has_initial_stack (c : Execution.Environment) (expectedEncapStack : Nat → List Nat)
    (sources : List Nat)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.payloadOrigin iface)
    {start : Execution.State} (origin : RedPayloadOrigin c sources start) :
    Execution.StackInvariant c expectedEncapStack start := by
  obtain ⟨member, datapathStage, entry, empty, ingress, authentication⟩ := origin
  obtain ⟨stack, admitted⟩ := sourceCheck start.iface member
  simp only [Execution.StackInvariant, datapathStage]
  refine ⟨⟨⟨?_, ?_, Or.inl authentication, ?_⟩, ?_⟩, entry⟩
  · simp [Execution.Frame.tags, empty, Execution.encapStackAfterIngress, authentication, entry, stack]
  · simpa [entry] using ingress
  · simp [entry]
  · simpa [entry] using admitted

theorem protected_red_stack_from_local_checks (c : Execution.Environment) (expectedEncapStack : Nat → List Nat)
    (sources blackIfaces : List Nat)
    (conditions : Execution.LocalStackConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.payloadOrigin iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1]) :
    msc_protected_red_payload_stack c sources blackIfaces := by
  intro start finish actions origin run ready black
  exact (Execution.transmitted_stack c expectedEncapStack conditions run
    (red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin) ready).trans
      (blackCheck finish.iface black)

theorem protected_black_execution_applies_layers_in_order
    (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (conditions : Execution.LocalStackConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.payloadOrigin iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    (layerShapes : ∀ iface, (expectedEncapStack iface).head? = some 2 → expectedEncapStack iface = [2, 1])
    {start finish : Execution.State} {actions : List Execution.Action}
    (origin : RedPayloadOrigin c sources start) (run : (Execution.lts c).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    Execution.OrderedEncryptions c 1 2 start actions finish := by
  have initial := red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin
  have stack := (Execution.transmitted_stack c expectedEncapStack conditions run initial ready).trans
    (blackCheck finish.iface black)
  apply Execution.nested_stack_requires_ordered_encryptions c expectedEncapStack conditions 1 2
    layerShapes run initial
  · simp [Execution.Frame.tags, origin.2.2.2.1]
  · simp [stack]

theorem fragmented_black_transmission_keeps_layers {Header Byte : Type} [DecidableEq Header]
    (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    (conditions : Execution.LocalStackConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.payloadOrigin iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Execution.Action)}
    (origin : RedPayloadOrigin c sources start.logical)
    (run : (Fragmentation.segmented (Execution.lts c) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] := by
  have preserved := Fragmentation.fragmented_execution_preserves_invariant
    (Fragmentation.segmented (Execution.lts c) encode) (Execution.lts c)
    Fragmentation.SegmentedState.logical
    (Fragmentation.segmented_projection_checked (Execution.lts c) encode)
    (Execution.StackInvariant c expectedEncapStack)
    (fun _ _ _ step invariant => Execution.step_preserves_stack_invariant conditions step invariant)
    run (red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin)
  have stack : finish.logical.frame.tags = expectedEncapStack finish.logical.iface := by
    simpa [Execution.StackInvariant, ready] using preserved
  exact stack.trans (blackCheck finish.logical.iface black)

theorem every_black_fragment_has_both_layers {Byte : Type}
    (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (encodedBytes : Execution.Frame → List Byte)
    (conditions : Execution.LocalStackConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.payloadOrigin iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    {start finish : Fragmentation.SegmentedState Execution.State Execution.FragmentDescriptor Byte}
    {actions : List (Option Execution.Action)}
    (origin : RedPayloadOrigin c sources start.logical) (whole : start.fragments = none)
    (run : (Fragmentation.segmented (Execution.lts c)
      (Execution.encodeForFragmentation encodedBytes)).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    ∀ pieces, finish.fragments = some pieces → ∀ piece ∈ pieces,
      piece.header.layers = [2, 1] ∧
      piece.header.payload = finish.logical.frame.payload ∧
      piece.header.originDomain = finish.logical.frame.originDomain ∧
      piece.header.source = finish.logical.frame.packet.source ∧
      piece.header.destination = finish.logical.frame.packet.destination := by
  have stack := fragmented_black_transmission_keeps_layers c expectedEncapStack sources blackIfaces
    (Execution.encodeForFragmentation encodedBytes) conditions sourceCheck blackCheck origin run ready black
  intro pieces existsPieces piece member
  rw [Execution.execution_fragment_descriptors_match c encodedBytes run whole pieces existsPieces piece member]
  exact ⟨stack, rfl, rfl, rfl, rfl⟩

end TDN.Targets
