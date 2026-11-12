import Mathlib.Data.List.Basic

/-! Balanced evidence trees provide checked witness lookups and complete leaf traversal. -/
namespace TDN.Certificates

variable {α β : Type}

inductive WitnessTree (α : Type) where
  | empty
  | leaf (value : α)
  | branch (left right : WitnessTree α)
  deriving Repr, DecidableEq

namespace WitnessTree

def values : WitnessTree α → List α
  | .empty => []
  | .leaf value => [value]
  | .branch left right => left.values ++ right.values

def lookup : WitnessTree α → List Bool → Option α
  | .leaf value, [] => some value
  | .branch left _, false :: rest => left.lookup rest
  | .branch _ right, true :: rest => right.lookup rest
  | _, _ => none

lemma lookup_mem (tree : WitnessTree α) (path : List Bool) (value : α)
    (found : tree.lookup path = some value) : value ∈ tree.values := by
  induction tree generalizing path with
  | empty => simp [lookup] at found
  | leaf item =>
    cases path <;> simp [lookup] at found
    simp [values, found]
  | branch left right ihLeft ihRight =>
    cases path with
    | nil => simp [lookup] at found
    | cons side rest =>
      cases side with
      | false => exact List.mem_append_left _ (ihLeft rest found)
      | true => exact List.mem_append_right _ (ihRight rest found)

def checkWith (check : α → β → Bool) : WitnessTree α → WitnessTree β → Bool
  | .empty, .empty => true
  | .leaf value, .leaf witness => check value witness
  | .branch left right, .branch first second =>
      checkWith check left first && checkWith check right second
  | _, _ => false

theorem checkWith_sound (check : α → β → Bool) (property : α → Prop)
    (sound : ∀ value witness, check value witness = true → property value)
    (tree : WitnessTree α) (witnesses : WitnessTree β)
    (checked : tree.checkWith check witnesses = true) :
    ∀ value ∈ tree.values, property value := by
  induction tree generalizing witnesses with
  | empty => simp [values]
  | leaf value =>
    cases witnesses <;> simp only [checkWith, Bool.false_eq_true] at checked
    rename_i witness
    simpa [values] using sound value witness checked
  | branch left right ihLeft ihRight =>
    cases witnesses <;> simp only [checkWith, Bool.false_eq_true] at checked
    rename_i first second
    have split : checkWith check left first = true ∧ checkWith check right second = true := by
      simpa only [Bool.and_eq_true] using checked
    obtain ⟨firstChecked, secondChecked⟩ := split
    intro value member
    rcases List.mem_append.mp member with member | member
    · exact ihLeft first firstChecked value member
    · exact ihRight second secondChecked value member

end WitnessTree

inductive NatIndex (α : Type) where
  | empty
  | node (value : Option α) (even odd : NatIndex α)
  deriving Repr, DecidableEq

def NatIndex.lookup : NatIndex α → Nat → Option α
  | .empty, _ => none
  | .node value _ _, 0 => value
  | .node _ even odd, key + 1 =>
      if (key + 1) % 2 = 0 then even.lookup ((key + 1) / 2)
      else odd.lookup ((key + 1) / 2)


inductive OrderedIndex (α : Type) where
  | empty
  | node (key : Nat) (value : α) (left right : OrderedIndex α)
  deriving Repr, DecidableEq

def OrderedIndex.lookup : OrderedIndex α → Nat → Option α
  | .empty, _ => none
  | .node pivot value left right, key =>
      if key = pivot then some value
      else if key < pivot then left.lookup key else right.lookup key

end TDN.Certificates
