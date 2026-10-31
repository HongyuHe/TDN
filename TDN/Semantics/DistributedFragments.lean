import TDN.Semantics.Fragmentation

namespace TDN.Fragmentation

inductive DistributedState (Logical Header Byte : Type) where
  | whole (logical : Logical)
  | pieces (located : List (Logical × Fragment Header Byte))

inductive DistributedStep {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte) :
    DistributedState Logical Header Byte → Option Action →
    DistributedState Logical Header Byte → Prop where
  | packet {before after action} (step : system.Tr before action after) :
      DistributedStep system encode (.whole before) (some action) (.whole after)
  | fragment {state pieces} (valid : ValidPieces (encode state) pieces) :
      DistributedStep system encode (.whole state) none
        (.pieces (pieces.map (fun piece => (state, piece))))
  | movePiece {earlier later before after action piece}
      (step : system.Tr before action after)
      (header : (encode before).header = (encode after).header)
      (bytes : (encode before).bytes = (encode after).bytes) :
      DistributedStep system encode (.pieces (earlier ++ (before, piece) :: later))
        (some action) (.pieces (earlier ++ (after, piece) :: later))
  | reassemble {state pieces} (valid : ValidPieces (encode state) pieces) :
      DistributedStep system encode (.pieces (pieces.map (fun piece => (state, piece))))
        none (.whole state)

def distributed {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte) :
    Cslib.LTS (DistributedState Logical Header Byte) (Option Action) where
  Tr := DistributedStep system encode

def DistributedInvariant {Logical Header Byte : Type}
    (encode : Logical → Datagram Header Byte) (invariant : Logical → Prop) :
    DistributedState Logical Header Byte → Prop
  | .whole state => invariant state
  | .pieces located => ∀ entry ∈ located,
      invariant entry.1 ∧ entry.2.header = (encode entry.1).header

lemma distributed_step_preserves {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte)
    (invariant : Logical → Prop) (preserved : system.TrInv invariant) :
    (distributed system encode).TrInv (DistributedInvariant encode invariant) := by
  intro before action after step valid
  cases step with
  | packet step => exact preserved _ _ _ step valid
  | fragment piecesValid =>
    intro entry member
    obtain ⟨piece, present, rfl⟩ := List.mem_map.mp member
    exact ⟨valid, piecesValid.2.1 piece present⟩
  | @movePiece earlier later before after action piece step header bytes =>
    intro entry member
    rcases List.mem_append.mp member with first | tail
    · exact valid entry (List.mem_append_left _ first)
    · rcases List.mem_cons.mp tail with equal | rest
      · subst entry
        have old := valid (before, piece) (by simp)
        exact ⟨preserved _ _ _ step old.1, old.2.trans header⟩
      · exact valid entry (List.mem_append_right _ (List.mem_cons_of_mem _ rest))
  | @reassemble state pieces piecesValid =>
    obtain ⟨piece, member⟩ := List.exists_mem_of_ne_nil pieces piecesValid.1
    exact (valid (state, piece) (List.mem_map.mpr ⟨piece, member, rfl⟩)).1

theorem distributed_execution_preserves {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte)
    (invariant : Logical → Prop) (preserved : system.TrInv invariant)
    {before after : DistributedState Logical Header Byte} {actions : List (Option Action)}
    (run : (distributed system encode).MTr before actions after)
    (initial : DistributedInvariant encode invariant before) :
    DistributedInvariant encode invariant after :=
  Cslib.LTS.mtrInv_of_trInv (distributed_step_preserves system encode invariant preserved)
    before actions after run initial

end TDN.Fragmentation
