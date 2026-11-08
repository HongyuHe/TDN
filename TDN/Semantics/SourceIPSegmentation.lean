import TDN.Semantics.SourceIPFragmentation

namespace TDN.PacketSource

def Request.segmentCapacity (request : Request) (mtu : Nat) : Nat :=
  min (mtu - request.Overhead) (request.ProtocolLimit - request.Overhead)

lemma Request.ip_overhead_bounds (request : Request) (packet : PacketPolicy.Packet)
    (body : request.body = .datagram packet) (valid : request.TemplateValid) :
    request.Overhead ≤ 120 ∧ 65535 ≤ request.ProtocolLimit := by
  have parts := valid
  simp only [Request.TemplateValid, body] at parts
  obtain ⟨network, transport, _, _, _⟩ := parts
  have networkBound : request.networkHeaderBytes ≤ 60 := by
    rcases network with ipv4 | ipv6 <;> omega
  have transportBound : request.transportHeaderBytes ≤ 60 := by
    rcases transport with udp | tcp | icmp <;> omega
  refine ⟨by unfold Request.Overhead; omega, ?_⟩
  simp only [Request.ProtocolLimit, body]
  split <;> omega

lemma Request.segment_capacity_positive (request : Request) (packet : PacketPolicy.Packet)
    (mtu : Nat) (body : request.body = .datagram packet) (valid : request.TemplateValid)
    (room : request.Overhead < mtu) : 0 < request.segmentCapacity mtu := by
  have bounds := request.ip_overhead_bounds packet body valid
  unfold Request.segmentCapacity
  omega

def sourceIPDatagrams (request : Request) (packet : PacketPolicy.Packet) (mtu : Nat) : List Datagram :=
  match request.mode with
  | .stream =>
      (Fragmentation.bytePartition request.application.length (request.segmentCapacity mtu)
        request.application).map (fun payload => (encodeSourceDatagram request packet payload).asWhole)
  | .datagram _ => [encodeFragmentedSourceDatagram request packet request.application mtu]

@[simp] lemma source_whole_application (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) :
    (encodeSourceDatagram request packet payload).asWhole.application = payload := rfl

theorem source_IP_datagrams_valid (request : Request) (packet : PacketPolicy.Packet) (mtu : Nat)
    (body : request.body = .datagram packet) (valid : request.TemplateValid)
    (representable : HeaderRepresentable packet) (minimum : 1280 ≤ mtu)
    (room : request.Overhead < mtu)
    (length : (∃ dontFragment, request.mode = .datagram dontFragment) →
      request.PacketSize ≤ request.ProtocolLimit)
    (dfFits : request.mode = .datagram true → request.MtuBytes ≤ mtu) :
    (Outcome.emitted (sourceIPDatagrams request packet mtu)).Valid request mtu := by
  have mtuOverhead : request.MtuOverhead = request.Overhead := by
    simp only [Request.MtuOverhead, body]
  refine ⟨valid, by rw [mtuOverhead]; exact room, ?_, ?_, ?_, ?_⟩
  · cases mode : request.mode with
    | stream =>
      simp only [sourceIPDatagrams, mode]
      intro empty
      have length := congrArg List.length empty
      simp only [List.length_map, List.length_nil] at length
      exact Fragmentation.byte_partition_nonempty _ _ _ (List.length_eq_zero_iff.mp length)
    | datagram df => simp [sourceIPDatagrams, mode]
  · cases mode : request.mode with
    | stream =>
      simp only [sourceIPDatagrams, mode, List.map_map]
      change (List.map id (Fragmentation.bytePartition request.application.length
        (request.segmentCapacity mtu) request.application)).flatten = request.application
      rw [List.map_id]
      exact Fragmentation.byte_partition_restores_bytes _ _ _
    | datagram df =>
      have preserved := source_IP_fragmentation_preserves request packet request.application mtu
      simp only [sourceIPDatagrams, mode, List.map_cons, List.map_nil, List.flatten_cons,
        List.flatten_nil, List.append_nil, preserved.2.1]
  · intro datagram member
    cases mode : request.mode with
    | stream =>
      simp only [sourceIPDatagrams, mode] at member
      obtain ⟨payload, inChunks, rfl⟩ := List.mem_map.mp member
      have bound := Fragmentation.byte_partition_piece_bound request.application.length
        (request.segmentCapacity mtu) request.application
        (request.segment_capacity_positive packet mtu body valid room) (Nat.le_refl _) payload inChunks
      have size : request.Overhead + payload.length ≤ mtu ∧
          request.Overhead + payload.length ≤ request.ProtocolLimit := by
        have overheadBound := request.ip_overhead_bounds packet body valid
        unfold Request.segmentCapacity at bound
        omega
      exact source_IP_whole_datagram_valid request packet payload mtu body valid representable size.2 size.1
    | datagram df =>
      simp only [sourceIPDatagrams, mode, List.mem_singleton] at member
      subst datagram
      apply source_IP_fragmented_datagram_valid request packet request.application mtu body valid
        representable (length ⟨df, mode⟩) minimum
      · intro stream
        rw [mode] at stream
        cases stream
      · intro dontFragment
        have fits := dfFits dontFragment
        simpa only [Request.MtuBytes, mtuOverhead] using fits
  · intro df mode
    simp only [sourceIPDatagrams, mode, List.length_singleton]

end TDN.PacketSource
