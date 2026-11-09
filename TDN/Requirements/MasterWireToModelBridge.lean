import TDN.Requirements.StandardTunnelMtuOverheads
import TDN.Models.L2BridgeMtuPreservation
import TDN.Models.IpsecEgressFragmentAndEmit

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource MultiProtocolForwarding IPsecFrameEncoding


def sizedEmission {Key : Type} {ifaces : List Nat} (codec : Codec Key)
    (mtu : Nat → Nat) (state : State ifaces) : Datagram :=
  wireEmission codec (sourceDatagram state) state.native.frame (mtu state.native.iface)


def sizedWireModel {Key : Type} {ifaces : List Nat} (codec : Codec Key)
    (mtu payloadLimit : Nat → Nat) : Msc.WireSizeModel (State ifaces) :=
  wireModel codec mtu payloadLimit (sizedEmission codec mtu)


theorem standard_reachable_Ethernet_size {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (links : EthernetMTUChecks prototype.configuration mtu)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (sourceMtu : prototype.sourceProcessing.sourceMtu = mtu)
    {start finish : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    EthernetSizeBound mtu finish.native := by
  have preserved : (model prototype ifaces d history).system.TrInv
      (fun state => EthernetSizeBound mtu state.native) := by
    intro before action after step bound
    exact device_step_preserves_Ethernet_size checks links step.2.2.2.1 bound
  have initialBound : EthernetSizeBound mtu start.native := by
    obtain ⟨request, datagrams, datagram, recorded, allowed, emitted, member, same⟩ := initialized.2
    have valid := emitted_datagram_valid emissions emitted member
    intro header body
    rw [same] at body ⊢
    change datagram.body = .ethernet header at body
    change (LinkAdmission.decodePayload (LinkAdmission.payloadCode datagram.application)).length ≤ mtu request.iface
    rw [LinkAdmission.decodePayload_payloadCode]
    rw [sourceMtu] at valid
    exact Ethernet_reassembly_size datagram header body _ valid.2.2.1 valid.1
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initialBound


theorem standard_reachable_wire_encoding {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (required : Nat → Bool) (mtu payloadLimit plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (links : EthernetMTUChecks prototype.configuration mtu)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (sourceMtu : prototype.sourceProcessing.sourceMtu = mtu) (minimum : ∀ iface, 1280 ≤ mtu iface)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    {start finish : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    (sizedWireModel codec mtu payloadLimit).WireEncoding (model prototype ifaces d history) finish := by
  obtain ⟨request, datagrams, source, recorded, allowed, emitted, member, valid, payload, origin, originalIP, originalEthernet⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  have sourceSame : sourceDatagram finish = source := by simp [sourceDatagram, recorded]
  have shape := standard_reachable_IPsec_shape prototype ifaces d history checks.noMAC checks.noCarriers
    checks.outboundIPv4 initialized run
  have coherent := standard_reachable_headers prototype ifaces d history processing mode headerBounds
    start finish actions initialized run
  have budget := (standard_reachable_size_budget prototype ifaces d history required mtu plaintextLimit
    authenticationLimit checks emissions processing mode headerBounds initialized run).1
  have ethernet := standard_reachable_Ethernet_size prototype ifaces d history required mtu plaintextLimit
    authenticationLimit checks links emissions sourceMtu initialized run
  change _ ∧ _ ∧ _
  dsimp only [sizedWireModel, wireModel, sizedEmission, model, binding, DeviceExecutionBinding.withProjection]
  simp only [encodedPayload, sourceSame]
  refine ⟨(wire_emission_raw codec source finish.native.frame _).trans
    (bare_emission_raw codec source finish.native.frame shape), ?_, ?_⟩
  · cases visible : finish.native.frame.visibleHeader with
    | some header =>
        exact wire_IP_reassembles codec source valid.1 finish.native.frame shape originalIP
          originalEthernet coherent plaintextLimit budget header visible _ (minimum _)
    | none =>
      cases body : finish.native.frame.body with
      | datagram header => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
      | ipsec association contents => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
      | macsec association contents => simp [body, Body.IPsecOnly] at shape
      | carrier endpoint contents => simp [body, Body.IPsecOnly] at shape
      | ethernet header =>
        have bounded := ethernet header body
        rw [payload] at bounded
        change (LinkAdmission.decodePayload (LinkAdmission.payloadCode source.application)).length ≤ _ at bounded
        rw [LinkAdmission.decodePayload_payloadCode] at bounded
        dsimp only [wireEmission]
        simp only [bareEmission, body]
        apply Datagram.whole_packet_reassembles_from_header
        · trivial
        · exact bounded
  · cases visible : finish.native.frame.visibleHeader with
    | some header =>
      have properties := bare_emission_IP_properties codec source valid.1 finish.native.frame shape originalIP
        originalEthernet coherent plaintextLimit budget header visible
      rw [wire_emission_body, wire_emission_raw]
      exact ⟨properties.1, by rw [(wire_emission_network codec source finish.native.frame _).1,
        (wire_emission_network codec source finish.native.frame _).2]; exact properties.2.1⟩
    | none =>
      cases body : finish.native.frame.body with
      | datagram header => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
      | ipsec association contents => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
      | macsec association contents => simp [body, Body.IPsecOnly] at shape
      | carrier endpoint contents => simp [body, Body.IPsecOnly] at shape
      | ethernet header =>
        have sourceBody : source.body = .ethernet header := by
          cases sourceCase : source.body with
          | ethernet nominal =>
            have same : header = nominal := by simpa only [body, sourceCase, Body.originalEthernet,
              Option.some.injEq] using originalEthernet
            simpa only [same] using sourceCase
          | datagram nominal => simp [body, sourceCase, Body.originalEthernet] at originalEthernet
          | ipsec association contents =>
            have impossible := valid.1
            simp [Datagram.Decoded, sourceCase] at impossible
          | macsec association contents =>
            have impossible := valid.1
            simp [Datagram.Decoded, sourceCase] at impossible
          | carrier endpoint contents =>
            have impossible := valid.1
            simp [Datagram.Decoded, sourceCase] at impossible
        have decoded := valid.1
        rw [Datagram.Decoded, sourceBody] at decoded
        refine ⟨header, ?_, ?_, ?_, ?_⟩
        · rw [wire_emission_body]
          simp only [bareEmission, body]
        · rw [(wire_emission_network codec source finish.native.frame _).1]
          simpa only [bareEmission, body] using decoded.2
        · intro original same
          exact Body.ethernet.inj same
        · simp [body, Body.isEthernetCiphertext]

end TDN.Requirements.StandardDataPlaneBridge
