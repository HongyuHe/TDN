import TDN.Requirements.UniqueOriginEnclaveBinding
import TDN.Requirements.ExtendedMscRoleSpecs
import TDN.Models.RecursiveEspWireCodec

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource IpsecFrameEncoding


def sourceDatagram {ifaces : List Nat} (state : State ifaces) : EncodedDatagram :=
  (state.source.map Prod.snd).getD
    { body := .ethernet ⟨0, 0, 0, []⟩, application := [], transportHeader := [],
      networkHeader := [], fragments := [] }


def encodedPayload {ifaces : List Nat} (state : State ifaces) : List UInt8 :=
  (sourceDatagram state).application


def wireModel {Key : Type} {ifaces : List Nat} (codec : Codec Key)
    (mtu payloadLimit : Nat → Nat) (emission : State ifaces → EncodedDatagram) : Msc.WireSizeModel (State ifaces) :=
  { payload := encodedPayload
    serialize := fun state body payload => encodeBody codec (sourceDatagram state) payload body
      state.deviceState.frame.activeHeader state.deviceState.frame.hiddenHeaders
    parse := fun state bytes => decodeFrame codec (sourceDatagram state) state.deviceState.frame bytes
    emission := emission, configuredMtu := mtu, configuredPayloadLimit := payloadLimit }


theorem standard_reachable_ipsec_shape {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (noMAC : prototype.configuration.macIfaces = []) (noCarriers : prototype.configuration.carriers = [])
    (installed : ∀ iface policy association,
      policy ∈ prototype.configuration.ip.egressPolicies iface →
      association ∈ prototype.configuration.ip.egressSAs iface →
      DataPlaneForwarding.saMatchesPolicy association policy → KnownIPv4Seal (policy.seal association))
    {start finish : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    finish.deviceState.frame.body.IPsecOnly KnownIPv4Seal := by
  have preserved : (model prototype ifaces d history).system.TrInv
      (fun state => state.deviceState.frame.body.IPsecOnly KnownIPv4Seal) := by
    intro before action after step shape
    exact MultiProtocolForwarding.step_preserves_ipsec_body_shape noMAC noCarriers
      KnownIPv4Seal installed step.2.2.2.1 shape
  have initialShape : start.deviceState.frame.body.IPsecOnly KnownIPv4Seal := by
    rcases initialized.1.2.1 with ⟨header, body⟩ | ⟨header, body⟩ <;>
      simp [body, Body.IPsecOnly]
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initialShape


theorem standard_wire_state_encoding {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (mtu payloadLimit : Nat → Nat) (emission : State ifaces → EncodedDatagram)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (processing : MultiProtocolForwarding.HeaderProcessing)
    (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : MultiProtocolForwarding.HeaderBounds processing)
    (noMAC : prototype.configuration.macIfaces = []) (noCarriers : prototype.configuration.carriers = [])
    (installed : ∀ iface policy association,
      policy ∈ prototype.configuration.ip.egressPolicies iface →
      association ∈ prototype.configuration.ip.egressSAs iface →
      DataPlaneForwarding.saMatchesPolicy association policy → KnownIPv4Seal (policy.seal association))
    (lengthDefinition : ∀ body payload, prototype.configuration.networkBytes body payload = networkLength body)
    (start finish : State ifaces) (actions : List (Action ifaces))
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    (wireModel codec mtu payloadLimit emission).StateEncoding (model prototype ifaces d history) finish := by
  obtain ⟨request, datagrams, datagram, recorded, _, _, _, valid, payload, _, originalIP, originalEthernet⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  have source : sourceDatagram finish = datagram := by simp [sourceDatagram, recorded]
  have shape := standard_reachable_ipsec_shape prototype ifaces d history noMAC noCarriers installed initialized run
  have coherent := standard_reachable_headers prototype ifaces d history processing mode headerBounds start finish
    actions initialized run
  have encodedLength := encoded_body_network_length codec datagram valid.1 finish.deviceState.frame.body
    shape originalIP originalEthernet finish.deviceState.frame.activeHeader finish.deviceState.frame.hiddenHeaders coherent
  have parsed := decode_encoded_body codec datagram datagram.application valid.1 finish.deviceState.frame.body
    shape originalIP originalEthernet finish.deviceState.frame.activeHeader finish.deviceState.frame.hiddenHeaders coherent
  change _ ∧ _ ∧ _ ∧ _ ∧ _
  dsimp only [wireModel, encodedPayload, model, binding, DeviceExecutionBinding.withProjection]
  rw [source]
  refine ⟨payload, ?_, encodedLength.2, ?_, ?_⟩
  · simp only [decodeFrame, parsed, Option.map_some]
  · rw [lengthDefinition, encodedLength.1]
    cases bodyHeader : finish.deviceState.frame.body.visibleHeader with
    | none => simp [TunnelFrame.visibleHeader, bodyHeader]
    | some nominal => simp [TunnelFrame.visibleHeader, bodyHeader]
  · intro header body
    have sourceBody := source_ip_body_from_original datagram valid.1 header (by simpa [body, Body.originalHeader] using originalIP)
    have decoded := valid.1
    rw [EncodedDatagram.Decoded, sourceBody] at decoded
    refine ⟨decoded.1, ?_⟩
    have length := encodedLength.1
    rw [body] at length
    simpa only [body, networkLength, Body.visibleHeader, Option.map_some] using length

theorem standard_wire_source_encoding {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (mtu payloadLimit : Nat → Nat) (emission : State ifaces → EncodedDatagram)
    (emissions : EmissionConditions prototype.sourceProcessing) :
    (wireModel codec mtu payloadLimit emission).SourceEncoding (model prototype ifaces d history) := by
  intro start request datagram initialized recorded
  change start.source = some (request, datagram) at recorded
  obtain ⟨initialRequest, datagrams, initialDatagram, initialRecorded, allowed, emitted, member, sameState⟩ :=
    initialized.2
  have same : (request, datagram) = (initialRequest, initialDatagram) :=
    Option.some.inj (recorded.symm.trans initialRecorded)
  have sameRequest := congrArg Prod.fst same
  have sameDatagram := congrArg Prod.snd same
  change request = initialRequest at sameRequest
  change datagram = initialDatagram at sameDatagram
  subst initialRequest
  subst initialDatagram
  have decoded := (emitted_datagram_valid emissions emitted member).1
  have source : sourceDatagram start = datagram := by simp [sourceDatagram, recorded]
  change encodeBody codec (sourceDatagram start) datagram.application datagram.body
    start.deviceState.frame.activeHeader start.deviceState.frame.hiddenHeaders = datagram.Raw
  rw [source, sameState]
  exact initial_body_serialization codec datagram decoded


end TDN.Requirements.StandardDataPlaneBridge
