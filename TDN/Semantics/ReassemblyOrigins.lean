import TDN.Semantics.Fragmentation

namespace TDN.ReassemblyOrigins

/-- Origin annotations describe where bytes came from. They are proof metadata,
not additional authenticated fields in an IP fragment header. Packet identities may
differ between pieces that share the same ordinary reassembly key. -/
structure ByteOrigin (Byte Domain PacketId : Type) where
  value : Byte
  domain : Domain
  packet : PacketId

/-- Assembly uses only the ordinary header key and offsets. It does not require
a preselected logical packet or equal ghost packet identities. -/
def assemble {Header Byte : Type} [DecidableEq Header]
    (header : Header) (pieces : List (Fragmentation.Fragment Header Byte)) :
    Option (Fragmentation.Datagram Header Byte) :=
  if pieces ≠ [] ∧ (∀ piece ∈ pieces, piece.header = header) ∧
      Fragmentation.Contiguous 0 pieces
  then some ⟨header, (pieces.map Fragmentation.Fragment.bytes).flatten⟩
  else none

def PieceSafe {Header Byte : Type} (safe : Byte → Prop)
    (piece : Fragmentation.Fragment Header Byte) : Prop :=
  ∀ byte ∈ piece.bytes, safe byte

def BufferSafe {Header Byte : Type} (safe : Byte → Prop)
    (pieces : List (Fragmentation.Fragment Header Byte)) : Prop :=
  ∀ piece ∈ pieces, PieceSafe safe piece

lemma flattened_bytes_safe {Header Byte : Type} {safe : Byte → Prop}
    {pieces : List (Fragmentation.Fragment Header Byte)}
    (checked : BufferSafe safe pieces) :
    ∀ byte ∈ (pieces.map Fragmentation.Fragment.bytes).flatten, safe byte := by
  intro byte member
  obtain ⟨bytes, inMap, contains⟩ := List.mem_flatten.mp member
  obtain ⟨piece, inPieces, equal⟩ := List.mem_map.mp inMap
  subst bytes
  exact checked piece inPieces byte contains

/-- Header collisions can combine several packets. They cannot introduce bytes
outside the allowed set when every admitted piece satisfies the local byte guard. -/
theorem assembled_bytes_inherit_piece_safety {Header Byte : Type}
    [DecidableEq Header] {header : Header}
    {pieces : List (Fragmentation.Fragment Header Byte)}
    {result : Fragmentation.Datagram Header Byte} {safe : Byte → Prop}
    (checked : BufferSafe safe pieces) (accepted : assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, safe byte := by
  unfold assemble at accepted
  split at accepted
  · cases accepted
    exact flattened_bytes_safe checked
  · contradiction

inductive Action where
  | receive | discard | clear
  deriving DecidableEq, Repr

/-- The ingress guard can depend on the observed input interface and association.
Its soundness is an explicit local implementation obligation. A buffer may contain
pieces from multiple source packets and may discard any subset. -/
inductive Step {Header Byte Input : Type}
    (acceptsPiece : Input → Fragmentation.Fragment Header Byte → Prop) :
    List (Fragmentation.Fragment Header Byte) → Action →
      List (Fragmentation.Fragment Header Byte) → Prop where
  | receive {before input piece} (accepted : acceptsPiece input piece) :
      Step acceptsPiece before .receive (before ++ [piece])
  | discard {before after} (retained : ∀ piece ∈ after, piece ∈ before) :
      Step acceptsPiece before .discard after
  | clear {before} : Step acceptsPiece before .clear []

def system {Header Byte Input : Type}
    (acceptsPiece : Input → Fragmentation.Fragment Header Byte → Prop) :
    Cslib.LTS (List (Fragmentation.Fragment Header Byte)) Action where
  Tr := Step acceptsPiece

lemma admission_preserves_byte_safety {Header Byte Input : Type}
    (acceptsPiece : Input → Fragmentation.Fragment Header Byte → Prop) (safe : Byte → Prop)
    (localGuard : ∀ input piece, acceptsPiece input piece → PieceSafe safe piece) :
    (system acceptsPiece).TrInv (BufferSafe safe) := by
  intro before action after step initial
  cases step with
  | receive accepted =>
    intro piece member
    rcases List.mem_append.mp member with old | added
    · exact initial piece old
    · have same := List.mem_singleton.mp added
      subst piece
      exact localGuard _ _ accepted
  | discard retained => exact fun piece member => initial piece (retained piece member)
  | clear => simp [BufferSafe]

/-- CSLib lifts the local fragment admission check to every finite buffer history.
No unique source-packet premise is used by this theorem. -/
theorem every_reassembly_history_preserves_byte_safety {Header Byte Input : Type}
    [DecidableEq Header]
    (acceptsPiece : Input → Fragmentation.Fragment Header Byte → Prop) (safe : Byte → Prop)
    (localGuard : ∀ input piece, acceptsPiece input piece → PieceSafe safe piece)
    {actions : List Action} {pieces : List (Fragmentation.Fragment Header Byte)}
    {header : Header} {result : Fragmentation.Datagram Header Byte}
    (run : (system acceptsPiece).MTr [] actions pieces)
    (accepted : assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, safe byte := by
  have initial : BufferSafe safe ([] : List (Fragmentation.Fragment Header Byte)) := by
    simp [BufferSafe]
  have invariant := Cslib.LTS.mtrInv_of_trInv
    (admission_preserves_byte_safety acceptsPiece safe localGuard) [] actions pieces run initial
  exact assembled_bytes_inherit_piece_safety invariant accepted

theorem reassembled_bytes_stay_in_admitted_domain
    {Header Byte Domain PacketId Input : Type} [DecidableEq Header]
    (acceptsPiece : Input → Fragmentation.Fragment Header (ByteOrigin Byte Domain PacketId) → Prop)
    (domain : Domain)
    (localGuard : ∀ input piece, acceptsPiece input piece →
      ∀ byte ∈ piece.bytes, byte.domain = domain)
    {actions : List Action}
    {pieces : List (Fragmentation.Fragment Header (ByteOrigin Byte Domain PacketId))}
    {header : Header} {result : Fragmentation.Datagram Header (ByteOrigin Byte Domain PacketId)}
    (run : (system acceptsPiece).MTr [] actions pieces)
    (accepted : assemble header pieces = some result) :
    ∀ byte ∈ result.bytes, byte.domain = domain :=
  every_reassembly_history_preserves_byte_safety acceptsPiece (fun byte => byte.domain = domain)
    localGuard run accepted

end TDN.ReassemblyOrigins
