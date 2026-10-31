import TDN.Targets.NestedPacketSizing

open TDN.Targets.NestedSizing

def esp := TDN.PacketLength.alignedWireLength 4 2 52

example : lengthAt esp esp .gray 1100 = 1156 := by decide
example : lengthAt esp esp .black 1100 = 1212 := by decide

/-- An Outer limit that fits only the Inner packet must fail the Black check. -/
example : ¬ lengthAt esp esp .black 1100 ≤ 1200 := by decide

/-- Gray limits apply to the once-protected packet, not the Black packet. -/
example : ∀ size, size ≤ 1100 → lengthAt esp esp .gray size ≤ 1200 := by
  intro size bound
  exact (length_at_monotone esp esp
    (TDN.PacketLength.aligned_wire_length_monotone 4 2 52)
    (TDN.PacketLength.aligned_wire_length_monotone 4 2 52) .gray bound).trans (by decide)

/-- The encompassing requirement uses the length present at each actual stage. -/
def stagedInner : TDN.Targets.PacketSizing where
  interface := 0
  role := .innerExternal
  family := .ipv4
  innerObjectiveSelected := true
  payloadLimit := 1100
  encapsulationOverheadBound := 118
  externalMtu := 1200
  outerMtu := 1400
  blackMtu := 1400
  ipv6PmtuConfigured := false
  encodedSize := esp
  outerEncodedSize := fun n => esp (esp n)
  blackEncodedSize := fun n => esp (esp n)

example : TDN.Targets.FitsSelectedPath stagedInner := by
  apply TDN.Targets.packet_sizes_fit_from_monotone_encoding
  · exact TDN.PacketLength.aligned_wire_length_monotone 4 2 52
  · exact fun _ _ h => TDN.PacketLength.aligned_wire_length_monotone 4 2 52
      (TDN.PacketLength.aligned_wire_length_monotone 4 2 52 h)
  · exact fun _ _ h => TDN.PacketLength.aligned_wire_length_monotone 4 2 52
      (TDN.PacketLength.aligned_wire_length_monotone 4 2 52 h)
  · intro impossible
    cases impossible
  · decide
  · decide
  · intro _
    decide
