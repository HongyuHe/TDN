import TDN.Requirements.StandardEthernetWireBridge

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource MultiProtocolForwarding IPsecFrameEncoding Msc


theorem standard_admitted_wire_budget {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (required : Nat → Bool) (mtu payloadLimit plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (links : EthernetMTUChecks prototype.configuration mtu)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (sourceMtu : prototype.sourceProcessing.sourceMtu = mtu) (minimum : ∀ iface, 1280 ≤ mtu iface)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    {start before after : State ifaces} {actions : List (Action ifaces)} {action : Action ifaces}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions before)
    (step : (model prototype ifaces d history).system.Tr before action after)
    (wire : (model prototype ifaces d history).native.action action = some .linkTransmit)
    (needed : required before.native.iface = true) :
    (encodedPayload before).length ≤ mtu before.native.iface ∧
    (sizedEmission codec mtu before).MtuBytes ≤ mtu before.native.iface := by
  have encoding := standard_wire_state_encoding prototype ifaces d history codec mtu payloadLimit
    (sizedEmission codec mtu) emissions processing mode headerBounds checks.noMAC checks.noCarriers
    checks.outboundIPv4 checks.networkDefinition start before actions initialized run
  have wireEncoding := standard_reachable_wire_encoding prototype ifaces d history codec required mtu
    payloadLimit plaintextLimit authenticationLimit checks links emissions sourceMtu minimum
    processing mode headerBounds initialized run
  cases visible : before.native.frame.visibleHeader with
  | some header =>
    have length := encoding.2.2.2.1
    dsimp only [model, binding, DeviceExecutionBinding.withProjection] at length
    rw [visible] at length
    change prototype.configuration.networkBytes before.native.frame.body before.native.frame.payload =
      some ((wireModel codec mtu payloadLimit (sizedEmission codec mtu)).serialize before
        before.native.frame.body (encodedPayload before)).length at length
    have bound := standard_admitted_IP_wire_fits prototype ifaces d history required mtu plaintextLimit
      authenticationLimit checks emissions processing mode headerBounds initialized run step wire needed _ length
    refine ⟨encoding.2.2.1.trans bound, ?_⟩
    have body := wireEncoding.2.2
    change (match before.native.frame.visibleHeader with
      | some header => _
      | none => _) at body
    rw [visible] at body
    dsimp only [sizedWireModel, wireModel] at body
    change (sizedEmission codec mtu before).MtuBytes ≤ _
    rw [Datagram.MtuBytes, body.1]
    change (sizedEmission codec mtu before).Raw.length ≤ _
    have raw := wireEncoding.1
    change (sizedEmission codec mtu before).Raw = _ at raw
    rw [raw]
    exact bound
  | none =>
    obtain ⟨request, datagrams, source, recorded, allowed, emitted, member, valid, payload, origin, originalIP, originalEthernet⟩ :=
      emitted_source_witness_preserved prototype ifaces d history emissions initialized run
    have sourceSame : sourceDatagram before = source := by simp [sourceDatagram, recorded]
    have shape := standard_reachable_IPsec_shape prototype ifaces d history checks.noMAC checks.noCarriers
      checks.outboundIPv4 initialized run
    cases body : before.native.frame.body with
    | datagram header => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
    | ipsec association contents => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
    | macsec association contents => simp [body, Body.IPsecOnly] at shape
    | carrier endpoint contents => simp [body, Body.IPsecOnly] at shape
    | ethernet header =>
      have bounded := standard_reachable_Ethernet_size prototype ifaces d history required mtu plaintextLimit
        authenticationLimit checks links emissions sourceMtu initialized run header body
      change (LinkAdmission.decodePayload before.native.frame.payload).length ≤ _ at bounded
      rw [payload] at bounded
      change (LinkAdmission.decodePayload (LinkAdmission.payloadCode source.application)).length ≤ _ at bounded
      rw [LinkAdmission.decodePayload_payloadCode] at bounded
      refine ⟨?_, ?_⟩
      · simpa only [encodedPayload, sourceSame] using bounded
      · dsimp only [sizedEmission]
        rw [sourceSame, wire_Ethernet_size codec source before.native.frame header body]
        exact bounded


def SettingsUseInterfaceCeilings (settings : List PacketSizing) (required : Nat → Bool)
    (mtu payloadLimit : Nat → Nat) : Prop :=
  ∀ setting ∈ settings, required setting.interface = true ∧
    setting.externalMtu = mtu setting.interface ∧ setting.payloadLimit = payloadLimit setting.interface ∧
    mtu setting.interface ≤ setting.payloadLimit ∧
    ∀ bytes, setting.encodedSize bytes = mtu setting.interface


theorem standard_packet_size_correspondence {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (required : Nat → Bool) (mtu payloadLimit plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (links : EthernetMTUChecks prototype.configuration mtu)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (sourceMtu : prototype.sourceProcessing.sourceMtu = mtu) (minimum : ∀ iface, 1280 ≤ mtu iface)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing) (settings : List PacketSizing)
    (settingsMatch : SettingsUseInterfaceCeilings settings required mtu payloadLimit) :
    (sizedWireModel codec mtu payloadLimit).Correspondence (model prototype ifaces d history) settings ∧
    (sizedWireModel codec mtu payloadLimit).NoFurtherFragmentation (model prototype ifaces d history) settings := by
  refine ⟨⟨standard_wire_source_encoding prototype ifaces d history codec mtu payloadLimit
    (sizedEmission codec mtu) emissions, ?_, ?_, ?_⟩, ?_⟩
  · intro setting member
    exact ⟨(settingsMatch setting member).2.1, (settingsMatch setting member).2.2.1⟩
  · intro start actions state initialized run
    exact standard_wire_state_encoding prototype ifaces d history codec mtu payloadLimit
      (sizedEmission codec mtu) emissions processing mode headerBounds checks.noMAC checks.noCarriers
      checks.outboundIPv4 checks.networkDefinition start state actions initialized run
  · intro start actions before action after initialized run step wire
    refine ⟨standard_reachable_wire_encoding prototype ifaces d history codec required mtu payloadLimit
      plaintextLimit authenticationLimit checks links emissions sourceMtu minimum processing mode headerBounds
      initialized run, ?_⟩
    intro setting member sameIface
    change setting.interface = before.native.iface at sameIface
    have facts := settingsMatch setting member
    have bound := standard_admitted_wire_budget prototype ifaces d history codec required mtu payloadLimit
      plaintextLimit authenticationLimit checks links emissions sourceMtu minimum processing mode headerBounds
      initialized run step wire (by simpa only [sameIface] using facts.1)
    refine ⟨?_, ?_⟩
    · exact bound.1.trans (by simpa only [sameIface] using facts.2.2.2.1)
    · rw [facts.2.2.2.2, sameIface]
      exact bound.2
  · intro start actions before action after setting initialized run step wire member sameIface role
    change setting.interface = before.native.iface at sameIface
    have facts := settingsMatch setting member
    have bound := standard_admitted_wire_budget prototype ifaces d history codec required mtu payloadLimit
      plaintextLimit authenticationLimit checks links emissions sourceMtu minimum processing mode headerBounds
      initialized run step wire (by simpa only [sameIface] using facts.1)
    exact wire_fitting_fragment_count codec (sourceDatagram before) before.native.frame _ bound.2

end TDN.Requirements.StandardDataPlaneBridge
