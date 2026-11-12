import TDN.Models.ReassemblyBufferDomainSafety
open TDN ReassemblyOrigins

abbrev B := ByteOrigin Nat Nat Nat
def first : Fragmentation.Fragment Nat B := ⟨42, 0, [⟨65, 1, 101⟩]⟩
def second : Fragmentation.Fragment Nat B := ⟨42, 1, [⟨66, 1, 202⟩]⟩
def foreign : Fragmentation.Fragment Nat B := ⟨42, 1, [⟨66, 2, 303⟩]⟩

-- Equal ordinary keys and contiguous offsets permit different original packet IDs.
example : (assemble 42 [first, second]).isSome = true := by native_decide
example : assemble 42 [first, second] = some ⟨42, [⟨65, 1, 101⟩, ⟨66, 1, 202⟩]⟩ := by
  simp [assemble, first, second, Fragmentation.Contiguous]

-- A different domain can also collide; header checks alone cannot exclude it.
example : (assemble 42 [first, foreign]).isSome = true := by native_decide
example : ¬ BufferSafe (fun byte : B => byte.domain = 1) [first, foreign] := by
  simp [BufferSafe, PieceSafe, first, foreign]

example : assemble 42 [first, first] = none := by
  simp [assemble, first, Fragmentation.Contiguous]

example : BufferSafe (fun byte : B => byte.domain = 1) [first, second] := by
  simp [BufferSafe, PieceSafe, first, second]
