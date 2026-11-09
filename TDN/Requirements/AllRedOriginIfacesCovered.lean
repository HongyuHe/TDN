import TDN.Requirements.StandardDataPlaneBridge
import TDN.Models.EndpointTransmitContract

namespace TDN.Compliance

def DeviceExecutionBinding.SourceOriginCompatible {S A : Type}
    (binding : DeviceExecutionBinding S A) (d : Deployment)
    (request : PacketSource.Request) (datagram : PacketSource.Datagram) : Prop :=
  match binding.origin request.originDomain with
  | .red _ => True
  | .management component => BodyManagement d datagram.body ∧
      d.LocalBodySource component (binding.ifaceName request.iface) datagram.body
  | .control component protocol => BodyControlProtocol d datagram.body protocol ∧
      d.LocalBodySource component (binding.ifaceName request.iface) datagram.body

lemma DeviceExecutionBinding.emitted_source_state_initial {S A : Type}
    (binding : DeviceExecutionBinding S A) (d : Deployment)
    (request : PacketSource.Request) (datagrams : List PacketSource.Datagram)
    (datagram : PacketSource.Datagram)
    (allowed : binding.SourceRequestAllowed d request)
    (emitted : binding.sourceProcessing.process request = .emitted datagrams)
    (member : datagram ∈ datagrams)
    (valid : datagram.ValidFor request (binding.sourceProcessing.sourceMtu request.iface))
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
    simpa [DeviceExecutionBinding.SourceRequestAllowed, origin,
      DeviceExecutionBinding.SourceState] using allowed.2.2
  | management component =>
    simp only [DeviceExecutionBinding.SourceRequestAllowed, origin] at allowed
    simp only [DeviceExecutionBinding.SourceOriginCompatible, origin] at compatible
    simp only [DeviceExecutionBinding.SourceState, origin]
    exact ⟨True.intro, compatible.1, allowed.2.2.2.1, compatible.2⟩
  | control component protocol =>
    simp only [DeviceExecutionBinding.SourceRequestAllowed, origin] at allowed
    simp only [DeviceExecutionBinding.SourceOriginCompatible, origin] at compatible
    simp only [DeviceExecutionBinding.SourceState, origin]
    exact ⟨True.intro, compatible.1, allowed.2.2.2.1, compatible.2⟩

end TDN.Compliance

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance

theorem standard_source_coverage {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    (errors : PacketSource.ErrorConditions prototype.sourceProcessing)
    (sourceIfaces : ∀ request, (binding prototype ifaces).SourceRequestAllowed d request →
      request.iface ∈ ifaces)
    (sourceOrigins : ∀ request datagrams datagram,
      (binding prototype ifaces).SourceRequestAllowed d request →
      prototype.sourceProcessing.process request = .emitted datagrams →
      datagram ∈ datagrams →
      (binding prototype ifaces).SourceOriginCompatible d request datagram)
    (networkSources : ∀ network ∈ d.networks, ∃ request datagrams,
      (binding prototype ifaces).SourceRequestAllowed d request ∧ request.application ≠ [] ∧
      prototype.origin request.originDomain = .red network.id ∧
      prototype.sourceProcessing.process request = .emitted datagrams) :
    (model prototype ifaces d history).SourceCoverage d := by
  have initialSource : ∀ request datagrams datagram,
      (binding prototype ifaces).SourceRequestAllowed d request →
      prototype.sourceProcessing.process request = .emitted datagrams →
      datagram ∈ datagrams →
      (binding prototype ifaces).SourceInitial d
        ((binding prototype ifaces).SourceState request datagram) := by
    intro request datagrams datagram allowed emitted member
    exact (binding prototype ifaces).emitted_source_state_initial d request datagrams datagram
      allowed emitted member (PacketSource.emitted_datagram_valid emissions emitted member)
      (sourceOrigins request datagrams datagram allowed emitted member)
  refine ⟨?_, ?_, ?_, ?_, networkSources⟩
  · intro request _
    exact PacketSource.processing_outcomes_valid prototype.sourceProcessing emissions errors request
  · intro request datagrams datagram allowed emitted member
    have source := initialSource request datagrams datagram allowed emitted member
    let start : State ifaces :=
      ⟨(binding prototype ifaces).SourceState request datagram,
        sourceIfaces request allowed, some (request, datagram)⟩
    refine ⟨source, start, ?_, rfl, rfl⟩
    exact ⟨source, request, datagrams, datagram, rfl, allowed, emitted, member, rfl⟩
  · intro state source
    obtain ⟨request, datagrams, datagram, allowed, emitted, member, _, same⟩ := source.2.2.1
    let start : State ifaces :=
      ⟨state, same ▸ sourceIfaces request allowed, some (request, datagram)⟩
    refine ⟨start, ?_, rfl⟩
    exact ⟨source, request, datagrams, datagram, rfl, allowed, emitted, member, same⟩
  · intro start initialized
    exact initialized

end TDN.Requirements.StandardDataPlaneBridge
