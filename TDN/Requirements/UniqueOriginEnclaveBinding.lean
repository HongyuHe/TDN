import TDN.Requirements.DataPlaneToEventTraceBridge
import TDN.Models.PayloadToNatEncoding

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame

theorem emitted_source_witness_preserved {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial before)
    (run : (model prototype ifaces d history).system.MTr before actions after) :
    ∃ request datagrams datagram,
      after.source = some (request, datagram) ∧
      (binding prototype ifaces).SourceRequestAllowed d request ∧
      prototype.sourceProcessing.process request = .emitted datagrams ∧
      datagram ∈ datagrams ∧
      datagram.ValidFor request (prototype.sourceProcessing.sourceMtu request.iface) ∧
      after.native.frame.payload = PayloadCode datagram.application ∧
      after.native.frame.originDomain = request.originDomain ∧
      after.native.frame.body.originalHeader = datagram.body.originalHeader ∧
      after.native.frame.body.originalEthernet = datagram.body.originalEthernet := by
  obtain ⟨request, datagrams, datagram, recorded, allowed, emitted, member, same⟩ := initialized.2
  have identity := source_identity_preserved prototype ifaces d history run
  refine ⟨request, datagrams, datagram, identity.2.2.2.2.trans recorded,
    allowed, emitted, member, PacketSource.emitted_datagram_valid emissions emitted member, ?_, ?_, ?_, ?_⟩
  · rw [identity.1, same]
    rfl
  · rw [identity.2.1, same]
    rfl
  · rw [identity.2.2.1, same]
    rfl
  · rw [identity.2.2.2.1, same]
    rfl

theorem plain_IP_payload_is_source_bytes {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial before)
    (run : (model prototype ifaces d history).system.MTr before actions after)
    (header : PacketPolicy.Packet) (plain : after.native.frame.body = .datagram header) :
    ∃ bytes, header.payloadBytes = some bytes ∧
      after.native.frame.payload = PayloadCode bytes := by
  obtain ⟨request, datagrams, datagram, _, _, _, _, valid, payload, _, original, _⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  have decoded := valid.1
  rw [plain] at original
  cases body : datagram.body with
  | datagram source =>
    have same : header = source := by simpa [Body.originalHeader, body] using original
    subst header
    simp only [PacketSource.Datagram.Decoded, body] at decoded
    exact ⟨datagram.application, decoded.1, payload⟩
  | ethernet source => simp [Body.originalHeader, body] at original
  | ipsec association contents => simp [PacketSource.Datagram.Decoded, body] at decoded
  | macsec association contents => simp [PacketSource.Datagram.Decoded, body] at decoded
  | carrier endpoint contents => simp [PacketSource.Datagram.Decoded, body] at decoded

theorem plain_Ethernet_has_source_serialization {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial before)
    (run : (model prototype ifaces d history).system.MTr before actions after)
    (header : EthernetHeader) (plain : after.native.frame.body = .ethernet header) :
    ∃ encoded : LinkAdmission.Frame,
      encoded.header = header ∧ encoded.Describes after.native.frame ∧
      after.native.frame.payload = PayloadCode encoded.payload := by
  obtain ⟨request, datagrams, datagram, _, _, _, _, valid, payload, _, _, original⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  have decoded := valid.1
  rw [plain] at original
  cases body : datagram.body with
  | datagram source => simp [Body.originalEthernet, body] at original
  | ethernet source =>
    have same : header = source := by simpa [Body.originalEthernet, body] using original
    subst header
    simp only [PacketSource.Datagram.Decoded, body] at decoded
    let encoded : LinkAdmission.Frame := ⟨source, datagram.networkHeader, datagram.application⟩
    refine ⟨encoded, rfl, ?_, payload⟩
    unfold LinkAdmission.Frame.Describes Frame.visibleHeader
    rw [plain]
    refine ⟨⟨decoded.2, rfl⟩, ?_⟩
    intro actual equal
    exact payload
  | ipsec association contents => simp [PacketSource.Datagram.Decoded, body] at decoded
  | macsec association contents => simp [PacketSource.Datagram.Decoded, body] at decoded
  | carrier endpoint contents => simp [PacketSource.Datagram.Decoded, body] at decoded


theorem serialized_Ethernet_payload_is_source_bytes {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial before)
    (run : (model prototype ifaces d history).system.MTr before actions after)
    (header : EthernetHeader) (plain : after.native.frame.body = .ethernet header)
    (encoded : LinkAdmission.Frame) (describes : encoded.Describes after.native.frame) :
    ∃ request datagram, after.source = some (request, datagram) ∧
      encoded.payload = datagram.application := by
  obtain ⟨request, datagrams, datagram, recorded, _, _, _, _, payload, _, _, _⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  refine ⟨request, datagram, recorded, ?_⟩
  apply LinkAdmission.payloadCode_injective
  exact (describes.plain_Ethernet_payload encoded after.native.frame header plain).symm.trans payload

theorem serialized_IP_application_is_source_bytes {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial before)
    (run : (model prototype ifaces d history).system.MTr before actions after)
    (header : PacketPolicy.Packet) (plain : after.native.frame.body = .datagram header)
    (encoded : LinkAdmission.Frame) (describes : encoded.Describes after.native.frame) :
    ∃ request datagram network transport,
      after.source = some (request, datagram) ∧
      encoded.payload = network ++ transport ++ datagram.application := by
  obtain ⟨request, datagrams, datagram, recorded, _, _, _, _, payload, _, _, _⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  obtain ⟨network, transport, bytes, serialization, bound⟩ :=
    describes.plain_IP_payload encoded after.native.frame header plain
  have same : bytes = datagram.application :=
    LinkAdmission.payloadCode_injective (bound.symm.trans payload)
  exact ⟨request, datagram, network, transport, recorded, same ▸ serialization⟩

theorem distinct_source_records_cannot_merge {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    {first second finish : State ifaces} {left right : List (Action ifaces)}
    (different : first.source ≠ second.source)
    (leftRun : (model prototype ifaces d history).system.MTr first left finish)
    (rightRun : (model prototype ifaces d history).system.MTr second right finish) : False := by
  exact different ((source_record_preserved prototype ifaces d history leftRun).symm.trans
    (source_record_preserved prototype ifaces d history rightRun))


theorem decoded_native_payload_is_source_bytes {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (emissions : PacketSource.EmissionConditions prototype.sourceProcessing)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial before)
    (run : (model prototype ifaces d history).system.MTr before actions after) :
    ∃ request datagram, after.source = some (request, datagram) ∧
      LinkAdmission.decodePayload after.native.frame.payload = datagram.application := by
  obtain ⟨request, datagrams, datagram, recorded, _, _, _, _, payload, _, _, _⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  refine ⟨request, datagram, recorded, ?_⟩
  rw [payload]
  exact LinkAdmission.decodePayload_payloadCode datagram.application

end TDN.Requirements.StandardDataPlaneBridge
