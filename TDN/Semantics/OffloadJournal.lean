import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.OffloadJournal

/-- Public transaction metadata describes a range of copied bytes. The body stays
outside the model. Its fingerprint binds the range to the retained observation. -/
structure Batch where
  offset : Nat
  next : Nat
  bytes : Nat
  fingerprint : String
  deriving DecidableEq, Repr

def finish (start : Nat) : List Batch → Nat
  | [] => start
  | batch :: rest => finish batch.next rest

/-- Every batch begins exactly where the previous one ended. The strict size
condition rules out empty entries that could obscure progress. -/
def Contiguous (start : Nat) : List Batch → Prop
  | [] => True
  | batch :: rest => batch.offset = start ∧ 0 < batch.bytes ∧
      batch.next = batch.offset + batch.bytes ∧ Contiguous batch.next rest

def contiguousDecidable (start : Nat) : (batches : List Batch) → Decidable (Contiguous start batches)
  | [] => isTrue trivial
  | batch :: rest => by
      haveI := contiguousDecidable batch.next rest
      unfold Contiguous
      infer_instance

instance (start : Nat) (batches : List Batch) : Decidable (Contiguous start batches) :=
  contiguousDecidable start batches

lemma finish_not_before_start {start : Nat} {batches : List Batch}
    (contiguous : Contiguous start batches) : start ≤ finish start batches := by
  induction batches generalizing start with
  | nil => simp [finish]
  | cons batch rest ih =>
    obtain ⟨offset, positive, size, tail⟩ := contiguous
    have lower := ih tail
    simp only [finish]
    omega

lemma member_ends_within_prefix {start : Nat} {batches : List Batch}
    (contiguous : Contiguous start batches) {batch : Batch} (member : batch ∈ batches) :
    batch.next ≤ finish start batches := by
  induction batches generalizing start with
  | nil => simp at member
  | cons first rest ih =>
    rcases List.mem_cons.mp member with same | later
    · subst batch
      exact finish_not_before_start contiguous.2.2.2
    · exact ih contiguous.2.2.2 later

/-- Checking adjacent boundaries establishes coverage of every byte position in
the committed prefix. Lean does not enumerate each position in the input file. -/
theorem contiguous_batches_cover_every_position {start : Nat} {batches : List Batch}
    (contiguous : Contiguous start batches) (position : Nat)
    (lower : start ≤ position) (upper : position < finish start batches) :
    ∃ batch ∈ batches, batch.offset ≤ position ∧ position < batch.next := by
  induction batches generalizing start with
  | nil => simp only [finish] at upper; omega
  | cons first rest ih =>
    obtain ⟨offset, positive, size, tail⟩ := contiguous
    by_cases inside : position < first.next
    · exact ⟨first, List.mem_cons_self .., by omega, inside⟩
    · obtain ⟨batch, member, covers⟩ := ih tail (by omega) upper
      exact ⟨batch, List.mem_cons_of_mem first member, covers⟩

/-- A validated acknowledgement identifies a committed batch and matches the
client's current source offset. Its advertised next offset is the batch end. -/
def Acknowledges (journal : List Batch) (cursor advertised : Nat) : Prop :=
  ∃ batch ∈ journal, batch.offset = cursor ∧ batch.next = advertised

theorem acknowledgement_stays_within_committed_data {journal : List Batch}
    (contiguous : Contiguous 0 journal) {cursor advertised : Nat}
    (acknowledged : Acknowledges journal cursor advertised) :
    advertised ≤ finish 0 journal := by
  obtain ⟨batch, member, offset, next⟩ := acknowledged
  rw [← next]
  exact member_ends_within_prefix contiguous member

end TDN.OffloadJournal
