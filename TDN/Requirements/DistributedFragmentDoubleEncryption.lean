import TDN.Requirements.DoubleEncryptionOnBlackLinks
import TDN.Models.MultiPathFragmentForwarding

namespace TDN.Requirements

theorem every_distributed_black_piece_is_double_protected {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    (conditions : DataPlaneForwarding.PerHopEncapConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : RedPayloadOrigin c sources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts c)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain := by
  let invariant := fun state : DataPlaneForwarding.State =>
    DataPlaneForwarding.EncapStackConsistent c expectedEncapStack state ∧ state.frame.payload = start.frame.payload ∧
      state.frame.originDomain = start.frame.originDomain
  have preserved : (DataPlaneForwarding.lts c).TrInv invariant := by
    intro before action after step valid
    obtain ⟨payload, domain⟩ := DataPlaneForwarding.step_preserves_payload step
    exact ⟨DataPlaneForwarding.hop_preserves_encap_stack conditions step valid.1,
      payload.trans valid.2.1, domain.trans valid.2.2⟩
  have initial : invariant start :=
    ⟨red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin, rfl, rfl⟩
  have checked := Fragmentation.distributed_forwarding_preserves (DataPlaneForwarding.lts c)
    (DataPlaneForwarding.encodeForFragmentation encodedBytes) invariant preserved run initial
  intro entry member ready black
  obtain ⟨valid, header⟩ := checked entry member
  have stack : entry.1.frame.encapLayerIds = expectedEncapStack entry.1.iface := by
    simpa [DataPlaneForwarding.EncapStackConsistent, ready] using valid.1
  rw [header]
  exact ⟨stack.trans (blackCheck entry.1.iface black), valid.2.1, valid.2.2⟩

end TDN.Requirements
