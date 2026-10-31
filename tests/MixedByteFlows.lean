import TDN.Evidence.FreshMixedByteProtection

open TDN MultiProtocolExecution
open TDN.Imported.PairingInnerMacsecOuterIpsec
open TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

private def source (state : MultiProtocolExecution.State) (_ : Nat) : Prop :=
  Targets.MixedRedOrigin redSources state

/-- Two received plaintext fragments may be interleaved/reordered and assembled.
No equality of origin packet identifiers participates in these steps. -/
example :
    (byteSystem config source).MTr [⟨usefulState1, ([1, 2, 3] : List Nat)⟩]
      [.split, .permute, .assemble] [⟨usefulState1, [2, 3, 1]⟩] := by
  have split :
      ByteFlows.Step (lts config) source PlainByteAssembly
        [⟨usefulState1, ([1, 2, 3] : List Nat)⟩] .split
        [⟨usefulState1, [1]⟩, ⟨usefulState1, [2, 3]⟩] :=
    .split (earlier := []) (later := []) (chunks := [[1], [2, 3]]) rfl
  have reorder :
      ByteFlows.Step (lts config) source PlainByteAssembly
        [⟨usefulState1, ([1] : List Nat)⟩, ⟨usefulState1, [2, 3]⟩] .permute
        [⟨usefulState1, [2, 3]⟩, ⟨usefulState1, [1]⟩] :=
    .permute (List.Perm.swap _ _ [])
  have compatible : PlainByteAssembly usefulState1 usefulState1 := by
    exact ⟨rfl, rfl, rfl, rfl, Or.inr ⟨_, rfl⟩⟩
  have assemble :
      ByteFlows.Step (lts config) source PlainByteAssembly
        [⟨usefulState1, ([2, 3] : List Nat)⟩, ⟨usefulState1, [1]⟩] .assemble
        [⟨usefulState1, [2, 3, 1]⟩] :=
    .assemble (earlier := []) (later := [])
      (packets := [⟨usefulState1, ([2, 3] : List Nat)⟩, ⟨usefulState1, [1]⟩]) (by simp)
      (by intro packet member; simp only [List.mem_cons, List.not_mem_nil, or_false] at member
          rcases member with rfl | rfl <;> exact compatible)
  exact .stepL split (.stepL reorder (.stepL assemble .refl))

/-- A MACsec body cannot use plaintext assembly as an authentication bypass. -/
example : ¬ PlainByteAssembly usefulState4 usefulState4 := by
  intro compatible
  have empty := compatible.2.2.2.1
  simp [usefulState4, LayeredFrame.Body.protectionLayers] at empty

example :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] :=
  positive_three_byte_delivery
