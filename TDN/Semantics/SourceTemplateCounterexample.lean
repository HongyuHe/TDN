import TDN.Semantics.SourceHeaderRepresentability
import TDN.Semantics.SourceProcessing

namespace TDN.PacketSource

def Request.TemplateValidBeforeRepresentability (request : Request) : Prop :=
  match request.body with
  | .datagram header =>
      ((header.source < 2^32 ∧ header.destination < 2^32 ∧
        5 ≤ header.ipv4HeaderWords ∧ header.ipv4HeaderWords ≤ 15 ∧
        request.networkHeaderBytes = 4 * header.ipv4HeaderWords) ∨
       (2^128 ≤ header.source ∧ header.source < 2^129 ∧
        2^128 ≤ header.destination ∧ header.destination < 2^129 ∧
        header.ipv4HeaderWords = 0 ∧ request.networkHeaderBytes = 40)) ∧
      ((header.protocol = "udp" ∧ request.transportHeaderBytes = 8) ∨
       (header.protocol = "tcp" ∧ 20 ≤ request.transportHeaderBytes ∧
        request.transportHeaderBytes ≤ 60 ∧ request.transportHeaderBytes % 4 = 0) ∨
       (header.protocol ∈ ["icmp", "icmpv6"] ∧ request.transportHeaderBytes = 8)) ∧
      header.sourcePort < 65536 ∧ header.destinationPort < 65536 ∧
      (request.mode = .stream → header.protocol = "tcp")
  | .ethernet header =>
      header.source < 2^48 ∧ header.destination < 2^48 ∧ header.etherType < 65536 ∧
      (∀ tag ∈ header.vlanTags, tag < 65536) ∧
      request.networkHeaderBytes = 14 + 4 * header.vlanTags.length ∧
      request.transportHeaderBytes = 0 ∧
      (∃ dontFragment, request.mode = .datagram dontFragment)
  | _ => False


def Outcome.ValidBeforeRepresentability (outcome : Outcome) (request : Request) (mtu : Nat) : Prop :=
  match outcome with
  | .emitted datagrams =>
      request.TemplateValidBeforeRepresentability ∧ request.MtuOverhead < mtu ∧ datagrams ≠ [] ∧
      (datagrams.map Datagram.application).flatten = request.application ∧
      (∀ datagram ∈ datagrams, datagram.ValidFor request mtu) ∧
      (∀ dontFragment, request.mode = .datagram dontFragment → datagrams.length = 1)
  | .error .unsupportedTemplate => ¬ request.TemplateValidBeforeRepresentability
  | .error .invalidMtu => request.TemplateValidBeforeRepresentability ∧ mtu ≤ request.MtuOverhead
  | .error .protocolLength => request.TemplateValidBeforeRepresentability ∧
      (∃ dontFragment, request.mode = .datagram dontFragment) ∧
      request.ProtocolLimit < request.PacketSize
  | .error .mtuExceeded => request.TemplateValidBeforeRepresentability ∧
      ((request.mode = .datagram true) ∨
        (∃ header, request.body = .ethernet header)) ∧ mtu < request.MtuBytes ∧
      request.PacketSize ≤ request.ProtocolLimit


theorem request_with_unrepresentable_hop_has_no_valid_outcome
    (request : Request) (packet : PacketPolicy.Packet) (mtu : Nat)
    (body : request.body = .datagram packet) (hop : 255 < packet.hopLimit)
    (template : request.TemplateValidBeforeRepresentability) (room : request.MtuOverhead < mtu)
    (length : request.PacketSize ≤ request.ProtocolLimit)
    (mode : request.mode = .datagram false) :
    ∀ outcome : Outcome, ¬ outcome.ValidBeforeRepresentability request mtu := by
  intro outcome valid
  cases outcome with
  | emitted datagrams =>
    obtain ⟨_, _, nonempty, _, datagramsValid, _⟩ := valid
    cases datagrams with
    | nil => exact nonempty rfl
    | cons datagram rest =>
      have bound := Datagram.valid_source_hop_bound body
        (datagramsValid datagram (List.mem_cons_self ..))
      omega
  | error reason =>
    cases reason with
    | unsupportedTemplate => exact valid template
    | invalidMtu => have invalid := valid.2; omega
    | protocolLength => have invalid := valid.2.2; omega
    | mtuExceeded =>
      rcases valid.2.1 with fragment | ethernet
      · rw [mode] at fragment
        cases fragment
      · obtain ⟨header, shape⟩ := ethernet
        rw [body] at shape
        cases shape

theorem request_with_unrepresentable_header_has_no_valid_outcome
    (request : Request) (packet : PacketPolicy.Packet) (mtu : Nat)
    (body : request.body = .datagram packet) (unrepresentable : ¬ HeaderRepresentable packet)
    (template : request.TemplateValidBeforeRepresentability) (room : request.MtuOverhead < mtu)
    (length : request.PacketSize ≤ request.ProtocolLimit)
    (mode : request.mode = .datagram false) :
    ∀ outcome : Outcome, ¬ outcome.ValidBeforeRepresentability request mtu := by
  intro outcome valid
  cases outcome with
  | emitted datagrams =>
    obtain ⟨_, _, nonempty, _, datagramsValid, _⟩ := valid
    cases datagrams with
    | nil => exact nonempty rfl
    | cons datagram rest =>
      have represented := Datagram.valid_source_header_representable body
        (datagramsValid datagram (List.mem_cons_self ..))
      exact unrepresentable represented
  | error reason =>
    cases reason with
    | unsupportedTemplate => exact valid template
    | invalidMtu => have invalid := valid.2; omega
    | protocolLength => have invalid := valid.2.2; omega
    | mtuExceeded =>
      rcases valid.2.1 with fragment | ethernet
      · rw [mode] at fragment
        cases fragment
      · obtain ⟨header, shape⟩ := ethernet
        rw [body] at shape
        cases shape

def oversizedHopRequest : Request :=
  { iface := 1, originDomain := 1,
    body := .datagram
      { source := 1, destination := 2, protocol := "udp", ingress := "", egress := "",
        sourcePort := 1234, destinationPort := 8080, ipv4HeaderWords := 5,
        inboundPolicies := [], outboundPolicies := [], connectionState := "NEW",
        hopLimit := 256, payloadBytes := some [1] },
    application := [1], networkHeaderBytes := 20, transportHeaderBytes := 8,
    mode := .datagram false }

lemma oversized_hop_old_template_is_allowed : oversizedHopRequest.TemplateValidBeforeRepresentability := by
  unfold Request.TemplateValidBeforeRepresentability oversizedHopRequest
  decide

theorem oversized_hop_request_cannot_be_processed :
    ∀ outcome : Outcome, ¬ outcome.ValidBeforeRepresentability oversizedHopRequest 1320 := by
  apply request_with_unrepresentable_hop_has_no_valid_outcome
    oversizedHopRequest _ 1320 rfl
  all_goals simp [oversizedHopRequest, Request.TemplateValidBeforeRepresentability, Request.MtuOverhead, Request.Overhead, Request.PacketSize, Request.ProtocolLimit ]


def ipv6NextHeaderMismatchRequest : Request :=
  { oversizedHopRequest with
    body := .datagram
      { source := 2^128 + 1, destination := 2^128 + 2,
        protocol := "udp", ingress := "", egress := "",
        sourcePort := 1234, destinationPort := 8080, ipv4HeaderWords := 0,
        inboundPolicies := [], outboundPolicies := [], connectionState := "NEW",
        hopLimit := 64, ipv6NextHeader := 0, payloadBytes := some [1] },
    networkHeaderBytes := 40 }

def nonzeroICMPPortRequest : Request :=
  { oversizedHopRequest with
    body := .datagram
      { source := 1, destination := 2, protocol := "icmp", ingress := "", egress := "",
        sourcePort := 1234, destinationPort := 0, ipv4HeaderWords := 5,
        inboundPolicies := [], outboundPolicies := [], connectionState := "NEW",
        hopLimit := 64, icmpType := 8, payloadBytes := some [1] } }

lemma ipv6_next_header_mismatch_old_template_is_allowed :
    ipv6NextHeaderMismatchRequest.TemplateValidBeforeRepresentability := by
  unfold Request.TemplateValidBeforeRepresentability ipv6NextHeaderMismatchRequest oversizedHopRequest
  decide

lemma nonzero_icmp_port_old_template_is_allowed : nonzeroICMPPortRequest.TemplateValidBeforeRepresentability := by
  unfold Request.TemplateValidBeforeRepresentability nonzeroICMPPortRequest oversizedHopRequest
  decide

theorem ipv6_next_header_mismatch_cannot_be_processed :
    ∀ outcome : Outcome, ¬ outcome.ValidBeforeRepresentability ipv6NextHeaderMismatchRequest 1320 := by
  apply request_with_unrepresentable_header_has_no_valid_outcome
    ipv6NextHeaderMismatchRequest _ 1320 rfl
  all_goals simp [ipv6NextHeaderMismatchRequest, oversizedHopRequest, HeaderRepresentable,
    protocolNumber, Request.TemplateValidBeforeRepresentability, Request.MtuOverhead, Request.Overhead,
    Request.PacketSize, Request.ProtocolLimit]

theorem nonzero_icmp_port_cannot_be_processed :
    ∀ outcome : Outcome, ¬ outcome.ValidBeforeRepresentability nonzeroICMPPortRequest 1320 := by
  apply request_with_unrepresentable_header_has_no_valid_outcome
    nonzeroICMPPortRequest _ 1320 rfl
  all_goals simp [nonzeroICMPPortRequest, oversizedHopRequest, HeaderRepresentable,
    protocolNumber, Request.TemplateValidBeforeRepresentability, Request.MtuOverhead, Request.Overhead,
    Request.PacketSize, Request.ProtocolLimit]

theorem oversized_hop_receives_valid_unsupported_result :
    processSource 1320 oversizedHopRequest = .error .unsupportedTemplate ∧
      (processSource 1320 oversizedHopRequest).Valid oversizedHopRequest 1320 := by
  exact ⟨by unfold processSource; rw [if_neg (by decide)], source_processing_valid _ _ (by decide)⟩

theorem ipv6_next_header_mismatch_receives_valid_unsupported_result :
    processSource 1320 ipv6NextHeaderMismatchRequest = .error .unsupportedTemplate ∧
      (processSource 1320 ipv6NextHeaderMismatchRequest).Valid ipv6NextHeaderMismatchRequest 1320 := by
  exact ⟨by unfold processSource; rw [if_neg (by decide)], source_processing_valid _ _ (by decide)⟩

theorem nonzero_icmp_port_receives_valid_unsupported_result :
    processSource 1320 nonzeroICMPPortRequest = .error .unsupportedTemplate ∧
      (processSource 1320 nonzeroICMPPortRequest).Valid nonzeroICMPPortRequest 1320 := by
  exact ⟨by unfold processSource; rw [if_neg (by decide)], source_processing_valid _ _ (by decide)⟩

end TDN.PacketSource
