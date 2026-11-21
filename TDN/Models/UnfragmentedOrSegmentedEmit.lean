import TDN.Models.EndpointTransmitSpec

namespace TDN.PacketSource

def EncodedDatagram.wholeFragment (datagram : EncodedDatagram) : EncodedFragment :=
  { networkHeader := datagram.networkHeader, data := datagram.Data, offset := 0, more := false }

def EncodedDatagram.asWhole (datagram : EncodedDatagram) : EncodedDatagram :=
  { datagram with fragments := [datagram.wholeFragment] }

@[simp] lemma EncodedDatagram.as_whole_body (datagram : EncodedDatagram) :
    datagram.asWhole.body = datagram.body := rfl

@[simp] lemma EncodedDatagram.as_whole_application (datagram : EncodedDatagram) :
    datagram.asWhole.application = datagram.application := rfl

@[simp] lemma EncodedDatagram.as_whole_raw (datagram : EncodedDatagram) :
    datagram.asWhole.Raw = datagram.Raw := rfl

@[simp] lemma EncodedDatagram.as_whole_mtu_bytes (datagram : EncodedDatagram) :
    datagram.asWhole.MtuBytes = datagram.MtuBytes := rfl

@[simp] lemma EncodedDatagram.as_whole_decoded (datagram : EncodedDatagram) :
    datagram.asWhole.Decoded ↔ datagram.Decoded := by
  rfl

@[simp] lemma EncodedDatagram.as_whole_header_from (datagram : EncodedDatagram) (request : Request) :
    datagram.asWhole.HeaderFrom request ↔ datagram.HeaderFrom request := by
  rfl

@[simp] lemma EncodedDatagram.as_whole_fragment_count (datagram : EncodedDatagram) :
    datagram.asWhole.fragments.length = 1 := rfl

lemma EncodedDatagram.whole_fragment_mtu_bytes (datagram : EncodedDatagram) :
    datagram.wholeFragment.MtuBytes datagram.body = datagram.MtuBytes := by
  cases body : datagram.body <;>
    simp [EncodedDatagram.wholeFragment, EncodedFragment.MtuBytes, EncodedDatagram.MtuBytes,
      EncodedFragment.Raw, EncodedDatagram.Raw, EncodedDatagram.Data, body]

lemma EncodedDatagram.whole_fragment_pieces_valid (datagram : EncodedDatagram) :
    Fragmentation.ValidPieces ⟨(), datagram.Data⟩
      (datagram.asWhole.fragments.map EncodedFragment.AsPiece) := by
  simp [Fragmentation.ValidPieces, Fragmentation.Contiguous, EncodedDatagram.asWhole,
    EncodedDatagram.wholeFragment, EncodedFragment.AsPiece]


def EncodedDatagram.UnfragmentedHeader (datagram : EncodedDatagram) : Prop :=
  match datagram.body with
  | .datagram packet => packet.source < 2^32 →
      field datagram.networkHeader 6 2 % 8192 = 0 ∧
      field datagram.networkHeader 6 2 / 8192 % 2 = 0
  | .ethernet _ => True
  | _ => False

lemma EncodedDatagram.decoded_header_is_unfragmented (datagram : EncodedDatagram)
    (decoded : datagram.Decoded) : datagram.UnfragmentedHeader := by
  cases body : datagram.body with
  | datagram packet =>
    simp only [EncodedDatagram.Decoded, body] at decoded
    simp only [EncodedDatagram.UnfragmentedHeader, body]
    exact fun ipv4 => (decoded.2.2.2.2 ipv4).2
  | ethernet packet => simp [EncodedDatagram.UnfragmentedHeader, body]
  | ipsec association body => simp [EncodedDatagram.Decoded, body] at decoded
  | macsec association body => simp [EncodedDatagram.Decoded, body] at decoded
  | macsecPdu association encryptFrames confidentialityOffset contents => simp [EncodedDatagram.Decoded, body] at decoded
  | carrier endpoint body => simp [EncodedDatagram.Decoded, body] at decoded

theorem EncodedDatagram.whole_packet_reassembles_from_header (datagram : EncodedDatagram) (mtu : Nat)
    (header : datagram.UnfragmentedHeader) (fits : datagram.MtuBytes ≤ mtu) :
    datagram.asWhole.Reassembles mtu := by
  refine ⟨datagram.whole_fragment_pieces_valid, ?_, ?_⟩
  · intro fragment member
    have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
    subst fragment
    refine ⟨?_, ?_⟩
    · simp [EncodedDatagram.wholeFragment, EncodedDatagram.asWhole, EncodedDatagram.Data]
    · simpa only [EncodedDatagram.as_whole_body, datagram.whole_fragment_mtu_bytes] using fits
  · cases body : datagram.body with
    | datagram packet =>
      simp only [EncodedDatagram.UnfragmentedHeader, body] at header
      simp only [EncodedDatagram.as_whole_body, body, EncodedDatagram.as_whole_fragment_count, ↓reduceIte]
      intro fragment member
      have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
      subst fragment
      exact ⟨rfl, rfl, rfl, header⟩
    | ethernet packet => simp [EncodedDatagram.asWhole, EncodedDatagram.wholeFragment, body]
    | ipsec association contents => simp [EncodedDatagram.UnfragmentedHeader, body] at header
    | macsec association contents => simp [EncodedDatagram.UnfragmentedHeader, body] at header
    | macsecPdu association encryptFrames confidentialityOffset contents => simp [EncodedDatagram.UnfragmentedHeader, body] at header
    | carrier endpoint contents => simp [EncodedDatagram.UnfragmentedHeader, body] at header

theorem EncodedDatagram.whole_packet_reassembles (datagram : EncodedDatagram) (mtu : Nat)
    (decoded : datagram.Decoded) (fits : datagram.MtuBytes ≤ mtu) :
    datagram.asWhole.Reassembles mtu := by
  refine ⟨datagram.whole_fragment_pieces_valid, ?_, ?_⟩
  · intro fragment member
    have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
    subst fragment
    refine ⟨?_, ?_⟩
    · simp [EncodedDatagram.wholeFragment, EncodedDatagram.asWhole, EncodedDatagram.Data]
    · simpa only [EncodedDatagram.as_whole_body, datagram.whole_fragment_mtu_bytes] using fits
  · cases body : datagram.body with
    | datagram header =>
      simp only [EncodedDatagram.Decoded, body] at decoded
      simp only [EncodedDatagram.as_whole_body, body, EncodedDatagram.as_whole_fragment_count, ↓reduceIte]
      intro fragment member
      have same : fragment = datagram.wholeFragment := List.mem_singleton.mp member
      subst fragment
      exact ⟨rfl, rfl, rfl, fun ipv4 => (decoded.2.2.2.2 ipv4).2⟩
    | ethernet header =>
      simp [EncodedDatagram.asWhole, EncodedDatagram.wholeFragment, body]
    | ipsec association body => simp [EncodedDatagram.Decoded, body] at decoded
    | macsec association body => simp [EncodedDatagram.Decoded, body] at decoded
    | macsecPdu association encryptFrames confidentialityOffset contents => simp [EncodedDatagram.Decoded, body] at decoded
    | carrier endpoint body => simp [EncodedDatagram.Decoded, body] at decoded

def EncodedDatagram.fragmentOnlyWhenNeeded (datagram : EncodedDatagram) (mtu : Nat) : EncodedDatagram :=
  if datagram.MtuBytes ≤ mtu then datagram.asWhole else datagram

@[simp] lemma EncodedDatagram.needed_fragmentation_preserves_raw (datagram : EncodedDatagram) (mtu : Nat) :
    (datagram.fragmentOnlyWhenNeeded mtu).Raw = datagram.Raw := by
  unfold EncodedDatagram.fragmentOnlyWhenNeeded
  split <;> rfl

lemma EncodedDatagram.fitting_packet_uses_one_fragment (datagram : EncodedDatagram) (mtu : Nat)
    (fits : datagram.MtuBytes ≤ mtu) :
    (datagram.fragmentOnlyWhenNeeded mtu).fragments.length = 1 := by
  simp [EncodedDatagram.fragmentOnlyWhenNeeded, fits]

theorem EncodedDatagram.fragment_only_when_needed_reassembles (datagram : EncodedDatagram) (mtu : Nat)
    (decoded : datagram.Decoded) (original : datagram.Reassembles mtu) :
    (datagram.fragmentOnlyWhenNeeded mtu).Reassembles mtu := by
  unfold EncodedDatagram.fragmentOnlyWhenNeeded
  split
  · exact datagram.whole_packet_reassembles mtu decoded ‹_›
  · exact original

end TDN.PacketSource
