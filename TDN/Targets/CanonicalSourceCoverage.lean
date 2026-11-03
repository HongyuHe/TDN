import TDN.Targets.CanonicalExecution
import TDN.Semantics.SourceCodec

namespace TDN.Compliance

def NativeExecutionBinding.SourceOriginCompatible {S A : Type}
    (binding : NativeExecutionBinding S A) (d : Deployment)
    (request : PacketSource.Request) (datagram : PacketSource.Datagram) : Prop :=
  match binding.origin request.originDomain with
  | .red _ => True
  | .management component => BodyManagement d datagram.body ∧
      d.LocalBodySource component (binding.portName request.port) datagram.body
  | .control component protocol => BodyControlProtocol d datagram.body protocol ∧
      d.LocalBodySource component (binding.portName request.port) datagram.body

lemma NativeExecutionBinding.emitted_source_state_initial {S A : Type}
    (binding : NativeExecutionBinding S A) (d : Deployment)
    (request : PacketSource.Request) (datagrams : List PacketSource.Datagram)
    (datagram : PacketSource.Datagram)
    (allowed : binding.SourceRequestAllowed d request)
    (emitted : binding.sourceProcessing.process request = .emitted datagrams)
    (member : datagram ∈ datagrams)
    (valid : datagram.ValidFor request (binding.sourceProcessing.sourceMtu request.port))
    (compatible : binding.SourceOriginCompatible d request datagram) :
    binding.SourceInitial d (binding.SourceState request datagram) := by
  have body : binding.SourceBody datagram.body := by
    have decoded := valid.1
    cases shape : datagram.body with
    | datagram header => exact Or.inl ⟨header, rfl⟩
    | ethernet header => exact Or.inr ⟨header, rfl⟩
    | ipsec association contents => simp [PacketSource.Datagram.Decoded, shape] at decoded
    | macsec association contents => simp [PacketSource.Datagram.Decoded, shape] at decoded
    | carrier endpoint contents => simp [PacketSource.Datagram.Decoded, shape] at decoded
  refine ⟨rfl, body, ⟨request, datagrams, datagram, allowed, emitted, member, valid, rfl⟩, ?_⟩
  cases origin : binding.origin request.originDomain with
  | red network =>
    simpa [NativeExecutionBinding.SourceRequestAllowed, origin,
      NativeExecutionBinding.SourceState] using allowed.2.2
  | management component =>
    simp only [NativeExecutionBinding.SourceRequestAllowed, origin] at allowed
    simp only [NativeExecutionBinding.SourceOriginCompatible, origin] at compatible
    simp only [NativeExecutionBinding.SourceState, origin]
    exact ⟨True.intro, compatible.1, allowed.2.2.2.1, compatible.2⟩
  | control component protocol =>
    simp only [NativeExecutionBinding.SourceRequestAllowed, origin] at allowed
    simp only [NativeExecutionBinding.SourceOriginCompatible, origin] at compatible
    simp only [NativeExecutionBinding.SourceState, origin]
    exact ⟨True.intro, compatible.1, allowed.2.2.2.1, compatible.2⟩

end TDN.Compliance

namespace TDN.Targets.CanonicalExecution
open Compliance

theorem canonical_source_coverage {S A : Type}
    (prototype : NativeExecutionBinding S A) (ports : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    (errors : PacketSource.ErrorConditions prototype.sourceProcessing)
    (sourcePorts : ∀ request, (binding prototype ports).SourceRequestAllowed d request →
      request.port ∈ ports)
    (sourceOrigins : ∀ request datagrams datagram,
      (binding prototype ports).SourceRequestAllowed d request →
      prototype.sourceProcessing.process request = .emitted datagrams →
      datagram ∈ datagrams →
      (binding prototype ports).SourceOriginCompatible d request datagram)
    (networkSources : ∀ network ∈ d.networks, ∃ request datagrams,
      (binding prototype ports).SourceRequestAllowed d request ∧ request.application ≠ [] ∧
      prototype.origin request.originDomain = .red network.id ∧
      prototype.sourceProcessing.process request = .emitted datagrams) :
    (model prototype ports d history).SourceCoverage d := by
  have initialSource : ∀ request datagrams datagram,
      (binding prototype ports).SourceRequestAllowed d request →
      prototype.sourceProcessing.process request = .emitted datagrams →
      datagram ∈ datagrams →
      (binding prototype ports).SourceInitial d
        ((binding prototype ports).SourceState request datagram) := by
    intro request datagrams datagram allowed emitted member
    exact (binding prototype ports).emitted_source_state_initial d request datagrams datagram
      allowed emitted member (PacketSource.emitted_datagram_valid emissions emitted member)
      (sourceOrigins request datagrams datagram allowed emitted member)
  refine ⟨?_, ?_, ?_, ?_, networkSources⟩
  · intro request _
    exact PacketSource.processing_outcomes_valid prototype.sourceProcessing emissions errors request
  · intro request datagrams datagram allowed emitted member
    have source := initialSource request datagrams datagram allowed emitted member
    let start : State ports :=
      ⟨(binding prototype ports).SourceState request datagram,
        sourcePorts request allowed, some (request, datagram)⟩
    refine ⟨source, start, ?_, rfl, rfl⟩
    exact ⟨source, request, datagrams, datagram, rfl, allowed, emitted, member, rfl⟩
  · intro state source
    obtain ⟨request, datagrams, datagram, allowed, emitted, member, _, same⟩ := source.2.2.1
    let start : State ports :=
      ⟨state, same ▸ sourcePorts request allowed, some (request, datagram)⟩
    refine ⟨start, ?_, rfl⟩
    exact ⟨source, request, datagrams, datagram, rfl, allowed, emitted, member, same⟩
  · intro start initialized
    exact initialized

end TDN.Targets.CanonicalExecution
