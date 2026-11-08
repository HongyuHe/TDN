import TDN.Semantics.PacketHeaderEncoding

namespace TDN.PacketSource

def ipv4FragmentFlags (offset : Nat) (more : Bool) : Nat :=
  offset / 8 + if more then 8192 else 0

def encodeIPv4Fragment (packet : PacketPolicy.Packet) (identity offset : Nat)
    (data : List UInt8) (more : Bool) : Fragment :=
  { networkHeader := encodeIPv4Header packet data.length identity (ipv4FragmentFlags offset more),
    data := data, offset := offset, more := more }

lemma ipv4_fragment_flags_bound (offset : Nat) (more : Bool) (bound : offset < 65536) :
    ipv4FragmentFlags offset more < 16384 := by
  cases more <;> simp only [ipv4FragmentFlags, Bool.false_eq_true, ↓reduceIte] <;> omega

theorem encoded_IPv4_fragment_fields (packet : PacketPolicy.Packet) (identity offset : Nat)
    (data : List UInt8) (more : Bool) (source : packet.source < 2^32)
    (destination : packet.destination < 2^32)
    (minimum : 5 ≤ packet.ipv4HeaderWords) (maximum : packet.ipv4HeaderWords ≤ 15)
    (size : 4 * packet.ipv4HeaderWords + data.length < 65536)
    (hop : packet.hopLimit < 256) (number : Nat)
    (protocolValue : protocolNumber packet.protocol = some number) (protocolBound : number < 256)
    (identifier : identity < 65536) (position : offset < 65536)
    (offsetAligned : offset % 8 = 0) (dataAligned : more = true → data.length % 8 = 0) :
    (encodeIPv4Fragment packet identity offset data more).IPv4Fields packet identity ∧
    field (encodeIPv4Fragment packet identity offset data more).networkHeader 6 2 / 16384 % 2 = 0 := by
  have flagsBound := ipv4_fragment_flags_bound offset more position
  have flags : field (encodeIPv4Fragment packet identity offset data more).networkHeader 6 2 =
      ipv4FragmentFlags offset more := encoded_IPv4_flags packet _ _ _ (by omega)
  refine ⟨⟨encoded_IPv4_header_matches packet data.length identity _ number source destination
    minimum maximum size hop protocolValue protocolBound,
    encoded_IPv4_identity packet _ _ _ identifier, ?_, ?_, dataAligned, offsetAligned⟩, ?_⟩
  all_goals dsimp only [encodeIPv4Fragment] at flags
  all_goals dsimp only [encodeIPv4Fragment]
  all_goals rw [flags]
  all_goals cases more <;> simp [ipv4FragmentFlags] at * <;> omega

@[simp] lemma encoded_IPv4_fragment_size (packet : PacketPolicy.Packet) (identity offset : Nat)
    (data : List UInt8) (more : Bool) (minimum : 5 ≤ packet.ipv4HeaderWords) :
    (encodeIPv4Fragment packet identity offset data more).MtuBytes (.datagram packet) =
      4 * packet.ipv4HeaderWords + data.length := by
  simp only [Fragment.MtuBytes, Fragment.Raw, encodeIPv4Fragment, List.length_append,
    encoded_IPv4_header_length packet data.length identity _ minimum]

end TDN.PacketSource
