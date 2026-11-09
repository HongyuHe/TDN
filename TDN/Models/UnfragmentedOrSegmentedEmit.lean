import TDN.Models.EndpointTransmitSpec

namespace TDN.PacketSource

def Datagram.wholeFragment (datagram : Datagram) : Fragment :=
  { networkHeader := datagram.networkHeader, data := datagram.Data, offset := 0, more := false }

def Datagram.asWhole (datagram : Datagram) : Datagram :=
  { datagram with fragments := [datagram.wholeFragment] }

@[simp] lemma Datagram.asWhole_body (datagram : Datagram) :
    datagram.asWhole.body = datagram.body := rfl

@[simp] lemma Datagram.asWhole_application (datagram : Datagram) :
    datagram.asWhole.application = datagram.application := rfl

@[simp] lemma Datagram.asWhole_raw (datagram : Datagram) :
    datagram.asWhole.Raw = datagram.Raw := rfl

@[simp] lemma Datagram.asWhole_mtuBytes (datagram : Datagram) :
    datagram.asWhole.MtuBytes = datagram.MtuBytes := rfl

@[simp] lemma Datagram.asWhole_decoded (datagram : Datagram) :
    datagram.asWhole.Decoded ↔ datagram.Decoded := by
  rfl

@[simp] lemma Datagram.asWhole_headerFrom (datagram : Datagram) (request : Request) :
    datagram.asWhole.HeaderFrom request ↔ datagram.HeaderFrom request := by
  rfl

@[simp] lemma Datagram.asWhole_fragment_count (datagram : Datagram) :
    datagram.asWhole.fragments.length = 1 := rfl

lemma Datagram.whole_fragment_mtuBytes (datagram : Datagram) :
    datagram.wholeFragment.MtuBytes datagram.body = datagram.MtuBytes := by
  cases body : datagram.body <;>
    simp [Datagram.wholeFragment, Fragment.MtuBytes, Datagram.MtuBytes,
      Fragment.Raw, Datagram.Raw, Datagram.Data, body]

lemma Datagram.whole_fragment_pieces_valid (datagram : Datagram) :
    Fragmentation.ValidPieces ⟨(), datagram.Data⟩
      (datagram.asWhole.fragments.map Fragment.AsPiece) := by
  simp [Fragmentation.ValidPieces, Fragmentation.Contiguous, Datagram.asWhole,
    Datagram.wholeFragment, Fragment.AsPiece]


def Datagram.UnfragmentedHeader (datagram : Datagram) : Prop :=
  match datagram.body with
  | .datagram packet => packet.source < 2^32 →
      field datagram.networkHeader 6 2 % 8192 = 0 ∧
      field datagram.networkHeader 6 2 / 8192 % 2 = 0
  | .ethernet _ => True
  | _ => False

lemma Datagram.decoded_header_is_unfragmented (datagram : Datagram)
    (decoded : datagram.Decoded) : datagram.UnfragmentedHeader := by
  cases body : datagram.body with
  | datagram packet =>
    simp only [Datagram.Decoded, body] at decoded
    simp only [Datagram.UnfragmentedHeader, body]
    exact fun ipv4 => (decoded.2.2.2.2 ipv4).2
  | ethernet packet => simp [Datagram.UnfragmentedHeader, body]
  | ipsec association body => simp [Datagram.Decoded, body] at decoded
  | macsec association body => simp [Datagram.Decoded, body] at decoded
  | carrier endpoint body => simp [Datagram.Decoded, body] at decoded

theorem Datagram.whole_packet_reassembles_from_header (datagram : Datagram) (mtu : Nat)
    (header : datagram.UnfragmentedHeader) (fits : datagram.MtuBytes ≤ mtu) :
    datagram.asWhole.Reassembles mtu := by
  refine ⟨datagram.whole_fragment_pieces_valid, ?_, ?_⟩
  · intro fragment member
    have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
    subst fragment
    refine ⟨?_, ?_⟩
    · simp [Datagram.wholeFragment, Datagram.asWhole, Datagram.Data]
    · simpa only [Datagram.asWhole_body, datagram.whole_fragment_mtuBytes] using fits
  · cases body : datagram.body with
    | datagram packet =>
      simp only [Datagram.UnfragmentedHeader, body] at header
      simp only [Datagram.asWhole_body, body, Datagram.asWhole_fragment_count, ↓reduceIte]
      intro fragment member
      have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
      subst fragment
      exact ⟨rfl, rfl, rfl, header⟩
    | ethernet packet => simp [Datagram.asWhole, Datagram.wholeFragment, body]
    | ipsec association contents => simp [Datagram.UnfragmentedHeader, body] at header
    | macsec association contents => simp [Datagram.UnfragmentedHeader, body] at header
    | carrier endpoint contents => simp [Datagram.UnfragmentedHeader, body] at header

theorem Datagram.whole_packet_reassembles (datagram : Datagram) (mtu : Nat)
    (decoded : datagram.Decoded) (fits : datagram.MtuBytes ≤ mtu) :
    datagram.asWhole.Reassembles mtu := by
  refine ⟨datagram.whole_fragment_pieces_valid, ?_, ?_⟩
  · intro fragment member
    have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
    subst fragment
    refine ⟨?_, ?_⟩
    · simp [Datagram.wholeFragment, Datagram.asWhole, Datagram.Data]
    · simpa only [Datagram.asWhole_body, datagram.whole_fragment_mtuBytes] using fits
  · cases body : datagram.body with
    | datagram header =>
      simp only [Datagram.Decoded, body] at decoded
      simp only [Datagram.asWhole_body, body, Datagram.asWhole_fragment_count, ↓reduceIte]
      intro fragment member
      have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
      subst fragment
      exact ⟨rfl, rfl, rfl, fun ipv4 => (decoded.2.2.2.2 ipv4).2⟩
    | ethernet header =>
      simp [Datagram.asWhole, Datagram.wholeFragment, body]
    | ipsec association body => simp [Datagram.Decoded, body] at decoded
    | macsec association body => simp [Datagram.Decoded, body] at decoded
    | carrier endpoint body => simp [Datagram.Decoded, body] at decoded

def Datagram.fragmentOnlyWhenNeeded (datagram : Datagram) (mtu : Nat) : Datagram :=
  if datagram.MtuBytes ≤ mtu then datagram.asWhole else datagram

@[simp] lemma Datagram.needed_fragmentation_preserves_raw (datagram : Datagram) (mtu : Nat) :
    (datagram.fragmentOnlyWhenNeeded mtu).Raw = datagram.Raw := by
  unfold Datagram.fragmentOnlyWhenNeeded
  split <;> rfl

lemma Datagram.fitting_packet_uses_one_fragment (datagram : Datagram) (mtu : Nat)
    (fits : datagram.MtuBytes ≤ mtu) :
    (datagram.fragmentOnlyWhenNeeded mtu).fragments.length = 1 := by
  simp [Datagram.fragmentOnlyWhenNeeded, fits]

theorem Datagram.fragment_only_when_needed_reassembles (datagram : Datagram) (mtu : Nat)
    (decoded : datagram.Decoded) (original : datagram.Reassembles mtu) :
    (datagram.fragmentOnlyWhenNeeded mtu).Reassembles mtu := by
  unfold Datagram.fragmentOnlyWhenNeeded
  split
  · exact datagram.whole_packet_reassembles mtu decoded ‹_›
  · exact original

end TDN.PacketSource
