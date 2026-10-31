import TDN.Semantics.FiniteExecution
import TDN.Semantics.ExecutionEvents
import TDN.Semantics.ExecutionFragments

namespace TDN.Targets

def RedPayloadOrigin (c : Execution.Config) (sources : List Nat) (s : Execution.State) : Prop :=
  s.port ∈ sources ∧ s.phase = .localOutput ∧
  s.frame.enteredPort = s.port ∧ s.frame.envelopes = [] ∧
  s.frame.packet.ingress = c.interfaceName s.port ∧ s.authenticated = []

def msc_protected_red_payload_stack (c : Execution.Config) (sources blackPorts : List Nat) : Prop :=
  ∀ start finish actions, RedPayloadOrigin c sources start →
    (Execution.lts c).MTr start actions finish → finish.phase = .ready →
    finish.port ∈ blackPorts → finish.frame.tags = [2, 1]

lemma red_origin_has_initial_stack (c : Execution.Config) (layout : Nat → List Nat)
    (sources : List Nat)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.payloadOrigin port)
    {start : Execution.State} (origin : RedPayloadOrigin c sources start) :
    Execution.StackInvariant c layout start := by
  obtain ⟨member, phase, entry, empty, ingress, authentication⟩ := origin
  obtain ⟨stack, admitted⟩ := sourceCheck start.port member
  simp only [Execution.StackInvariant, phase]
  refine ⟨⟨⟨?_, ?_, Or.inl authentication, ?_⟩, ?_⟩, entry⟩
  · simp [Execution.Frame.tags, empty, Execution.processingStack, authentication, entry, stack]
  · simpa [entry] using ingress
  · simp [entry]
  · simpa [entry] using admitted

theorem protected_red_stack_from_local_checks (c : Execution.Config) (layout : Nat → List Nat)
    (sources blackPorts : List Nat)
    (conditions : Execution.LocalStackConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.payloadOrigin port)
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1]) :
    msc_protected_red_payload_stack c sources blackPorts := by
  intro start finish actions origin run ready black
  exact (Execution.transmitted_stack c layout conditions run
    (red_origin_has_initial_stack c layout sources sourceCheck origin) ready).trans
      (blackCheck finish.port black)

theorem protected_black_execution_applies_layers_in_order
    (c : Execution.Config) (layout : Nat → List Nat) (sources blackPorts : List Nat)
    (conditions : Execution.LocalStackConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.payloadOrigin port)
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1])
    (layerShapes : ∀ port, (layout port).head? = some 2 → layout port = [2, 1])
    {start finish : Execution.State} {actions : List Execution.Action}
    (origin : RedPayloadOrigin c sources start) (run : (Execution.lts c).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    Execution.OrderedEncryptions c 1 2 start actions finish := by
  have initial := red_origin_has_initial_stack c layout sources sourceCheck origin
  have stack := (Execution.transmitted_stack c layout conditions run initial ready).trans
    (blackCheck finish.port black)
  apply Execution.nested_stack_requires_ordered_encryptions c layout conditions 1 2
    layerShapes run initial
  · simp [Execution.Frame.tags, origin.2.2.2.1]
  · simp [stack]

theorem fragmented_black_transmission_keeps_layers {Header Byte : Type} [DecidableEq Header]
    (c : Execution.Config) (layout : Nat → List Nat) (sources blackPorts : List Nat)
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    (conditions : Execution.LocalStackConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.payloadOrigin port)
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1])
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Execution.Action)}
    (origin : RedPayloadOrigin c sources start.logical)
    (run : (Fragmentation.segmented (Execution.lts c) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] := by
  have preserved := Fragmentation.fragmented_execution_preserves_invariant
    (Fragmentation.segmented (Execution.lts c) encode) (Execution.lts c)
    Fragmentation.SegmentedState.logical
    (Fragmentation.segmented_projection_checked (Execution.lts c) encode)
    (Execution.StackInvariant c layout)
    (fun _ _ _ step invariant => Execution.step_preserves_stack_invariant conditions step invariant)
    run (red_origin_has_initial_stack c layout sources sourceCheck origin)
  have stack : finish.logical.frame.tags = layout finish.logical.port := by
    simpa [Execution.StackInvariant, ready] using preserved
  exact stack.trans (blackCheck finish.logical.port black)

theorem every_black_fragment_has_both_layers {Byte : Type}
    (c : Execution.Config) (layout : Nat → List Nat) (sources blackPorts : List Nat)
    (encodedBytes : Execution.Frame → List Byte)
    (conditions : Execution.LocalStackConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.payloadOrigin port)
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1])
    {start finish : Fragmentation.SegmentedState Execution.State Execution.FragmentDescriptor Byte}
    {actions : List (Option Execution.Action)}
    (origin : RedPayloadOrigin c sources start.logical) (whole : start.fragments = none)
    (run : (Fragmentation.segmented (Execution.lts c)
      (Execution.encodeForFragmentation encodedBytes)).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    ∀ pieces, finish.fragments = some pieces → ∀ piece ∈ pieces,
      piece.header.layers = [2, 1] ∧
      piece.header.payload = finish.logical.frame.payload ∧
      piece.header.originDomain = finish.logical.frame.originDomain ∧
      piece.header.source = finish.logical.frame.packet.source ∧
      piece.header.destination = finish.logical.frame.packet.destination := by
  have stack := fragmented_black_transmission_keeps_layers c layout sources blackPorts
    (Execution.encodeForFragmentation encodedBytes) conditions sourceCheck blackCheck origin run ready black
  intro pieces existsPieces piece member
  rw [Execution.execution_fragment_descriptors_match c encodedBytes run whole pieces existsPieces piece member]
  exact ⟨stack, rfl, rfl, rfl, rfl⟩

end TDN.Targets
