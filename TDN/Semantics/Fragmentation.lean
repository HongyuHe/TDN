import Cslib.Foundations.Semantics.LTS.Simulation
import Mathlib.Data.List.Basic

namespace TDN.Fragmentation

/-- Header is the metadata selected by an abstraction. Ghost origin or protection
annotations are not wire reassembly keys. A concrete implementation must justify their
preservation separately; equal ordinary fragment keys do not imply equal origins. -/
structure Datagram (Header Byte : Type) where
  header : Header
  bytes : List Byte

structure Fragment (Header Byte : Type) where
  header : Header
  offset : Nat
  bytes : List Byte

def split {Header Byte : Type} (packet : Datagram Header Byte) (size : Nat) :
    Fragment Header Byte × Fragment Header Byte :=
  (⟨packet.header, 0, packet.bytes.take size⟩,
   ⟨packet.header, (packet.bytes.take size).length, packet.bytes.drop size⟩)

def join {Header Byte : Type} [DecidableEq Header]
    (first second : Fragment Header Byte) : Option (Datagram Header Byte) :=
  if first.header = second.header ∧ first.offset = 0 ∧ second.offset = first.bytes.length
  then some ⟨first.header, first.bytes ++ second.bytes⟩ else none

theorem split_preserves_header {Header Byte : Type} (packet : Datagram Header Byte) (size : Nat) :
    (split packet size).1.header = packet.header ∧
    (split packet size).2.header = packet.header := ⟨rfl, rfl⟩

theorem reassembly_restores_bytes {Header Byte : Type} [DecidableEq Header]
    (packet : Datagram Header Byte) (size : Nat) :
    join (split packet size).1 (split packet size).2 = some packet := by
  cases packet
  simp [join, split]

/-- Internal fragment bookkeeping uses none; a visible network operation retains its label. -/
def stuttering {State Action : Type} (system : Cslib.LTS State Action) :
    Cslib.LTS State (Option Action) where
  Tr before action after := match action with
    | none => before = after
    | some label => system.Tr before label after

/-- A detailed implementation step either preserves the datagram projection or performs one
modeled network operation. This local implementation contract includes reassembly validation. -/
def StepProjection {Detailed Abstract Action : Type}
    (detailed : Cslib.LTS Detailed (Option Action)) (abstract : Cslib.LTS Abstract Action)
    (project : Detailed → Abstract) : Prop :=
  ∀ before action after, detailed.Tr before action after →
    (stuttering abstract).Tr (project before) action (project after)

theorem projection_is_simulation {Detailed Abstract Action : Type}
    (detailed : Cslib.LTS Detailed (Option Action)) (abstract : Cslib.LTS Abstract Action)
    (project : Detailed → Abstract) (checked : StepProjection detailed abstract project) :
    Cslib.LTS.IsSimulation detailed (stuttering abstract) (fun d a => project d = a) := by
  intro d a equal action after step
  subst a
  exact ⟨project after, checked d action after step, rfl⟩

lemma stuttering_preserves_invariant {State Action : Type} (system : Cslib.LTS State Action)
    (invariant : State → Prop) (preserved : system.TrInv invariant) :
    (stuttering system).TrInv invariant := by
  intro before action after step initial
  cases action with
  | none => exact step ▸ initial
  | some label => exact preserved before label after step initial

/-- CSLib simulation transfers the datagram invariant to every fragmented execution.
The result applies to all matching implementations, not merely one size or one observed trace. -/
theorem fragmented_execution_preserves_invariant {Detailed Abstract Action : Type}
    (detailed : Cslib.LTS Detailed (Option Action)) (abstract : Cslib.LTS Abstract Action)
    (project : Detailed → Abstract) (checked : StepProjection detailed abstract project)
    (invariant : Abstract → Prop) (preserved : abstract.TrInv invariant)
    {before after : Detailed} {actions : List (Option Action)}
    (run : detailed.MTr before actions after) (initial : invariant (project before)) :
    invariant (project after) := by
  obtain ⟨finish, matched, equal⟩ :=
    (projection_is_simulation detailed abstract project checked).sim_trace rfl actions after run
  have result := Cslib.LTS.mtrInv_of_trInv
    (stuttering_preserves_invariant abstract invariant preserved)
    (project before) actions finish matched initial
  simpa [← equal] using result

/-- Every fragment has the same inherited metadata and a contiguous nonoverlapping offset.
The byte concatenation defines the reassembled body. These are finite local assembly checks. -/
def Contiguous {Header Byte : Type} (offset : Nat) :
    List (Fragment Header Byte) → Prop
  | [] => True
  | first :: rest => first.offset = offset ∧ Contiguous (offset + first.bytes.length) rest

instance {Header Byte : Type} (offset : Nat) (pieces : List (Fragment Header Byte)) :
    Decidable (Contiguous offset pieces) := by
  induction pieces generalizing offset with
  | nil => exact isTrue trivial
  | cons first rest ih =>
    unfold Contiguous
    haveI := ih (offset + first.bytes.length)
    infer_instance

def ValidPieces {Header Byte : Type} (packet : Datagram Header Byte)
    (pieces : List (Fragment Header Byte)) : Prop :=
  pieces ≠ [] ∧ (∀ piece ∈ pieces, piece.header = packet.header) ∧
    Contiguous 0 pieces ∧ (pieces.map Fragment.bytes).flatten = packet.bytes

def makePieces {Header Byte : Type} (header : Header) (offset : Nat) :
    List (List Byte) → List (Fragment Header Byte)
  | [] => []
  | bytes :: rest => ⟨header, offset, bytes⟩ :: makePieces header (offset + bytes.length) rest

lemma made_pieces_metadata {Header Byte : Type} (header : Header) (offset : Nat)
    (chunks : List (List Byte)) :
    (∀ piece ∈ makePieces header offset chunks, piece.header = header) ∧
    Contiguous offset (makePieces header offset chunks) ∧
    ((makePieces header offset chunks).map Fragment.bytes).flatten = chunks.flatten := by
  induction chunks generalizing offset with
  | nil => simp [makePieces, Contiguous]
  | cons bytes rest ih =>
    obtain ⟨headers, contiguous, body⟩ := ih (offset + bytes.length)
    refine ⟨?_, ⟨rfl, contiguous⟩, ?_⟩
    · intro piece member
      rcases List.mem_cons.mp member with equal | tail
      · subst piece
        rfl
      · exact headers piece tail
    · simp [makePieces, body]

theorem arbitrary_partition_is_valid {Header Byte : Type} (packet : Datagram Header Byte)
    (chunks : List (List Byte)) (nonempty : chunks ≠ []) (body : chunks.flatten = packet.bytes) :
    ValidPieces packet (makePieces packet.header 0 chunks) := by
  obtain ⟨headers, contiguous, restored⟩ := made_pieces_metadata packet.header 0 chunks
  refine ⟨?_, headers, contiguous, restored.trans body⟩
  cases chunks with
  | nil => exact False.elim (nonempty rfl)
  | cons first rest => simp [makePieces]

/-- Any finite number of simultaneous fragments can be carried. A valid assembly preserves
the logical packet; malformed, overlapping or inconsistent assemblies have no reassembly step. -/
structure SegmentedState (Logical Header Byte : Type) where
  logical : Logical
  fragments : Option (List (Fragment Header Byte))

inductive SegmentedStep {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte) :
    SegmentedState Logical Header Byte → Option Action →
    SegmentedState Logical Header Byte → Prop where
  | packet {before after action} (step : system.Tr before action after) :
      SegmentedStep system encode ⟨before, none⟩ (some action) ⟨after, none⟩
  | fragment {state pieces} (valid : ValidPieces (encode state) pieces) :
      SegmentedStep system encode ⟨state, none⟩ none ⟨state, some pieces⟩
  | moveFragments {before after action pieces}
      (step : system.Tr before action after)
      (header : (encode before).header = (encode after).header)
      (bytes : (encode before).bytes = (encode after).bytes) :
      SegmentedStep system encode ⟨before, some pieces⟩ (some action) ⟨after, some pieces⟩
  | reassemble {state pieces} (valid : ValidPieces (encode state) pieces) :
      SegmentedStep system encode ⟨state, some pieces⟩ none ⟨state, none⟩

def segmented {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte) :
    Cslib.LTS (SegmentedState Logical Header Byte) (Option Action) where
  Tr := SegmentedStep system encode

theorem segmented_projection_checked {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte) :
    StepProjection (segmented system encode) system SegmentedState.logical := by
  intro before action after step
  cases step with
  | packet step => exact step
  | fragment => rfl
  | moveFragments step header bytes => exact step
  | reassemble => rfl

/-- The fragment-list invariant binds each in-flight piece to the projected datagram. -/
def PiecesConsistent {Logical Header Byte : Type}
    (encode : Logical → Datagram Header Byte) (state : SegmentedState Logical Header Byte) : Prop :=
  ∀ pieces, state.fragments = some pieces → ValidPieces (encode state.logical) pieces

lemma segmented_preserves_piece_consistency {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte) :
    (segmented system encode).TrInv (PiecesConsistent encode) := by
  intro before action after step consistent
  cases step with
  | packet => intro pieces equal; cases equal
  | fragment valid => intro pieces equal; cases equal; exact valid
  | moveFragments step header bytes =>
    intro pieces equal
    have valid := consistent pieces equal
    rcases valid with ⟨nonempty, headers, offsets, body⟩
    exact ⟨nonempty, fun piece member => (headers piece member).trans header,
      offsets, body.trans bytes⟩
  | reassemble => intro pieces equal; cases equal

theorem execution_preserves_piece_consistency {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte)
    {before after : SegmentedState Logical Header Byte} {actions : List (Option Action)}
    (run : (segmented system encode).MTr before actions after)
    (initial : PiecesConsistent encode before) : PiecesConsistent encode after :=
  Cslib.LTS.mtrInv_of_trInv (segmented_preserves_piece_consistency system encode)
    before actions after run initial

theorem arbitrary_partition_reassembles {Logical Header Byte Action : Type}
    (system : Cslib.LTS Logical Action) (encode : Logical → Datagram Header Byte)
    (state : Logical) (chunks : List (List Byte))
    (nonempty : chunks ≠ []) (body : chunks.flatten = (encode state).bytes) :
    (segmented system encode).MTr ⟨state, none⟩ [none, none] ⟨state, none⟩ := by
  have valid := arbitrary_partition_is_valid (encode state) chunks nonempty body
  exact .stepL (.fragment valid) (.stepL (.reassemble valid) .refl)

end TDN.Fragmentation
