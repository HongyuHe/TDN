import TDN.Semantics.AuthenticatedAssembly

open TDN AuthenticatedAssembly

private abbrev Annotation := List Nat × Nat
private def message : Message Nat Nat Nat Annotation := ⟨7, 11, [10, 20, 30], ([101, 102], 1)⟩
private def other : Message Nat Nat Nat Annotation := ⟨7, 22, [10, 20, 30], ([101, 102], 2)⟩
private def decoded : Decoded Nat Nat (List Nat) := ⟨7, [10, 20, 30], [101, 102]⟩
private def produces (record : Message Nat Nat Nat Annotation) : Prop :=
  record = message ∨ record = other
private def authenticates (published : List (Message Nat Nat Nat Annotation))
    (result : Decoded Nat Nat (List Nat)) : Prop :=
  published.any (fun record => decide (record.context = result.context ∧
    record.wire = result.wire ∧ record.annotation.1 = result.plaintext)) = true
private def first : Fragmentation.Fragment Nat Nat := ⟨99, 0, [10]⟩
private def second : Fragmentation.Fragment Nat Nat := ⟨99, 1, [20, 30]⟩
private def start : State Nat Nat Nat Nat Annotation (List Nat) := ⟨[], [], []⟩
private def emitted : State Nat Nat Nat Nat Annotation (List Nat) := ⟨[message], [], []⟩
private def receivedFirst : State Nat Nat Nat Nat Annotation (List Nat) := ⟨[message], [first], []⟩
private def receivedBoth : State Nat Nat Nat Nat Annotation (List Nat) := ⟨[message], [first, second], []⟩
private def finish : State Nat Nat Nat Nat Annotation (List Nat) := ⟨[message], [], [decoded]⟩

example : AuthenticationSound Eq Prod.fst authenticates := by
  intro published result verified
  obtain ⟨record, member, matching⟩ := List.any_eq_true.mp verified
  refine ⟨record, member, ?_⟩
  change record.context = result.context ∧ record.wire = result.wire ∧
    record.annotation.1 = result.plaintext
  exact of_decide_eq_true matching

example : (system produces authenticates).MTr start
    [.publish, .receive, .receive, .accept] finish := by
  have publish : Step produces authenticates start .publish emitted :=
    .publish (Or.inl rfl)
  have receiveFirst : Step produces authenticates emitted .receive receivedFirst := .receive
  have receiveSecond : Step produces authenticates receivedFirst .receive receivedBoth := .receive
  have accept : Step produces authenticates receivedBoth .accept finish :=
    .accept (header := 99) (packet := ⟨99, [10, 20, 30]⟩)
      (by simp [ReassemblyOrigins.assemble, receivedBoth, first, second, Fragmentation.Contiguous])
      (by unfold authenticates; decide)
  exact .stepL publish (.stepL receiveFirst (.stepL receiveSecond (.stepL accept .refl)))

/-- Ordinary header and offset checks permit a mixed ciphertext. No such complete
codeword exists in the illustrative ideal authentication relation. -/
example : ReassemblyOrigins.assemble 99
    [first, (⟨99, 1, [50, 60]⟩ : Fragmentation.Fragment Nat Nat)] =
    some ⟨99, [10, 50, 60]⟩ := by
  simp [ReassemblyOrigins.assemble, first, Fragmentation.Contiguous]

example : ¬ authenticates [message, other] ⟨7, [10, 50, 60], [101, 102]⟩ := by
  unfold authenticates
  decide

/-- Two different producer/domain annotations can match the same decoded bytes.
Neither a decoder nor the proof is allowed to discard the second possibility. -/
example : Matches Eq Prod.fst message decoded ∧ Matches Eq Prod.fst other decoded := by
  constructor <;> exact ⟨rfl, rfl, rfl⟩

example : ¬ (∀ record ∈ [message, other], Matches Eq Prod.fst record decoded →
    record.annotation.2 = 1) := by
  intro all
  have wrong := all other (by simp) ⟨rfl, rfl, rfl⟩
  contradiction

/-- Actual key identity, direction and accepted epoch all matter. These Nat
values are an illustrative model fixture, not observed secret fingerprints. -/
private def sent : Context Nat Nat Nat := ⟨7, 2, 50, 1, 3⟩
example : Compatible Eq sent sent := ⟨rfl, rfl, rfl, rfl, rfl⟩
example : ¬ Compatible Eq sent { sent with secret := 8 } := by
  simp [Compatible, sent]
example : ¬ Compatible Eq sent { sent with direction := 2 } := by
  simp [Compatible, sent]
example : ¬ Compatible Eq sent { sent with epoch := 4 } := by
  simp [Compatible, sent]
example : Compatible (fun earlier current : Nat => earlier ≤ current)
    sent { sent with epoch := 4 } := by
  simp [Compatible, sent]
