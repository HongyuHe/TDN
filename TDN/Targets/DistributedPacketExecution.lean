import TDN.Targets.PacketExecution
import TDN.Semantics.DistributedFragments

namespace TDN.Targets

theorem every_distributed_black_piece_is_double_protected {Byte : Type}
    (c : Execution.Config) (layout : Nat → List Nat) (sources blackPorts : List Nat)
    (encodedBytes : Execution.Frame → List Byte)
    (conditions : Execution.LocalStackConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.payloadOrigin port)
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1])
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : RedPayloadOrigin c sources start)
    (run : (Fragmentation.distributed (Execution.lts c)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain := by
  let invariant := fun state : Execution.State =>
    Execution.StackInvariant c layout state ∧ state.frame.payload = start.frame.payload ∧
      state.frame.originDomain = start.frame.originDomain
  have preserved : (Execution.lts c).TrInv invariant := by
    intro before action after step valid
    obtain ⟨payload, domain⟩ := Execution.step_preserves_payload step
    exact ⟨Execution.step_preserves_stack_invariant conditions step valid.1,
      payload.trans valid.2.1, domain.trans valid.2.2⟩
  have initial : invariant start :=
    ⟨red_origin_has_initial_stack c layout sources sourceCheck origin, rfl, rfl⟩
  have checked := Fragmentation.distributed_execution_preserves (Execution.lts c)
    (Execution.encodeForFragmentation encodedBytes) invariant preserved run initial
  intro entry member ready black
  obtain ⟨valid, header⟩ := checked entry member
  have stack : entry.1.frame.tags = layout entry.1.port := by
    simpa [Execution.StackInvariant, ready] using valid.1
  rw [header]
  exact ⟨stack.trans (blackCheck entry.1.port black), valid.2.1, valid.2.2⟩

end TDN.Targets
