import TDN.Targets.SourceObservation

namespace TDN.Compliance
open PacketSource

theorem source_processing_preserves_origins {S A : Type} (binding : NativeExecutionBinding S A)
    (d : Deployment) (mtu : Nat → Nat) (processing : binding.sourceProcessing = sourceProcessing mtu)
    (minimum : ∀ iface, 1280 ≤ mtu iface) (noUDPBindings : d.udpBindings = [])
    (request : Request) (datagrams : List Datagram) (datagram : Datagram)
    (allowed : binding.SourceRequestAllowed d request)
    (emitted : binding.sourceProcessing.process request = .emitted datagrams)
    (member : datagram ∈ datagrams) : binding.SourceOriginCompatible d request datagram := by
  rw [processing] at emitted
  have template := (source_processing_emission_conditions mtu minimum).template request datagrams emitted
  change processSource (mtu request.iface) request = .emitted datagrams at emitted
  rcases allowed.1 with ⟨packet, body⟩ | ⟨header, body⟩
  · have shape := source_IP_emission_shape request packet _ datagrams body emitted
    rw [shape] at member
    obtain ⟨payload, datagramBody, payloadShape⟩ :=
      source_IP_datagrams_have_source_headers request packet _ datagram body template member
    have same : packet.payloadBytes = some payload ∨ packet.protocol = "tcp" := by
      rcases payloadShape with same | same | tcp
      · exact Or.inl same
      · subst payload
        exact Or.inl (by simpa only [Request.PayloadMatches, body] using allowed.2.1)
      · exact Or.inr tcp
    cases origin : binding.origin request.originDomain with
    | red network => simp only [NativeExecutionBinding.SourceOriginCompatible, origin]
    | management component =>
      simp only [NativeExecutionBinding.SourceRequestAllowed, origin] at allowed
      simp only [NativeExecutionBinding.SourceOriginCompatible, origin, datagramBody]
      exact ⟨(source_header_management d request packet payload noUDPBindings same).mpr
          (by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.1),
        (source_header_local_body_source d component (binding.ifaceName request.iface) request packet payload).mpr
          (by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.2.2)⟩
    | control component protocol =>
      simp only [NativeExecutionBinding.SourceRequestAllowed, origin] at allowed
      simp only [NativeExecutionBinding.SourceOriginCompatible, origin, datagramBody]
      exact ⟨(source_header_control d request packet payload protocol noUDPBindings same).mpr
          (by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.1),
        (source_header_local_body_source d component (binding.ifaceName request.iface) request packet payload).mpr
          (by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.2.2)⟩
  · have shape := source_Ethernet_emission_shape request header _ datagrams body emitted
    rw [shape] at member
    have same := List.mem_singleton.mp member
    subst datagram
    cases origin : binding.origin request.originDomain with
    | red network => simp only [NativeExecutionBinding.SourceOriginCompatible, origin]
    | management component =>
      simp only [NativeExecutionBinding.SourceRequestAllowed, origin] at allowed
      simp only [NativeExecutionBinding.SourceOriginCompatible, origin]
      exact ⟨by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.1,
        by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.2.2⟩
    | control component protocol =>
      simp only [NativeExecutionBinding.SourceRequestAllowed, origin] at allowed
      simp only [NativeExecutionBinding.SourceOriginCompatible, origin]
      exact ⟨by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.1,
        by simpa only [body, Datagram.asWhole_body, encodeSourceEthernet] using allowed.2.2.2.2⟩

end TDN.Compliance

namespace TDN.Targets.CanonicalExecution
open Compliance PacketSource

theorem canonical_generated_source_coverage {S A : Type}
    (prototype : NativeExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (mtu : Nat → Nat) (processing : prototype.sourceProcessing = sourceProcessing mtu)
    (minimum : ∀ iface, 1280 ≤ mtu iface) (noUDPBindings : d.udpBindings = [])
    (sourceIfaces : ∀ request, (binding prototype ifaces).SourceRequestAllowed d request → request.iface ∈ ifaces)
    (networkSources : ∀ network ∈ d.networks, ∃ request datagrams,
      (binding prototype ifaces).SourceRequestAllowed d request ∧ request.application ≠ [] ∧
      prototype.origin request.originDomain = .red network.id ∧
      prototype.sourceProcessing.process request = .emitted datagrams) :
    (model prototype ifaces d history).SourceCoverage d := by
  apply canonical_source_coverage prototype ifaces d history
  · rw [processing]
    exact source_processing_emission_conditions mtu minimum
  · rw [processing]
    exact source_processing_error_conditions mtu minimum
  · exact sourceIfaces
  · intro request datagrams datagram allowed emitted member
    exact source_processing_preserves_origins (binding prototype ifaces) d mtu processing minimum
      noUDPBindings request datagrams datagram allowed emitted member
  · exact networkSources

end TDN.Targets.CanonicalExecution
