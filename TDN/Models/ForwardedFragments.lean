import TDN.Models.EncapStackPreservation
import TDN.Models.DatagramFragmentationAndSimulation

namespace TDN.DataPlaneForwarding

structure FragmentDescriptor where
  payload : Nat
  originDomain : Nat
  source : Nat
  destination : Nat
  layers : List Nat
  deriving DecidableEq, Repr

def fragmentDescriptor (state : State) : FragmentDescriptor :=
  ⟨state.frame.payload, state.frame.originDomain, state.frame.packet.source,
    state.frame.packet.destination, state.frame.encapLayerIds⟩

def encodeForFragmentation {Byte : Type} (encodedBytes : Frame → List Byte)
    (state : State) : Fragmentation.Datagram FragmentDescriptor Byte :=
  ⟨fragmentDescriptor state, encodedBytes state.frame⟩

theorem forwarding_fragment_descriptors_match {Byte : Type} (c : DataPlaneModel)
    (encodedBytes : Frame → List Byte)
    {before after : Fragmentation.SegmentedState State FragmentDescriptor Byte}
    {actions : List (Option Action)}
    (run : (Fragmentation.segmented (lts c) (encodeForFragmentation encodedBytes)).MTr
      before actions after)
    (whole : before.fragments = none) :
    ∀ pieces, after.fragments = some pieces →
      ∀ piece ∈ pieces, piece.header = fragmentDescriptor after.logical := by
  have initial : Fragmentation.PiecesConsistent (encodeForFragmentation encodedBytes) before := by
    intro pieces equal
    rw [whole] at equal
    cases equal
  have consistent := Fragmentation.forwarding_preserves_piece_consistency
    (lts c) (encodeForFragmentation encodedBytes) run initial
  intro pieces equal piece member
  exact (consistent pieces equal).2.1 piece member

end TDN.DataPlaneForwarding
