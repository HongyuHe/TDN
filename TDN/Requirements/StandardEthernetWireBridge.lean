import TDN.Requirements.MasterWireToModelBridge
import TDN.Models.IpsecOverEthernetWireCodec

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource MultiProtocolForwarding IPsecFrameEncoding


theorem standard_reachable_link_frame_describes {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    {start finish : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    (linkEncoding codec finish.native.frame).Describes finish.native.frame := by
  obtain ⟨request, datagrams, source, recorded, allowed, emitted, member, valid, payload, origin, originalIP, originalEthernet⟩ :=
    emitted_source_witness_preserved prototype ifaces d history emissions initialized run
  have payloadCode : finish.native.frame.payload = LinkAdmission.payloadCode source.application := payload
  have root := standard_root_properties source valid.1 finish.native.frame originalIP originalEthernet payloadCode
  have shape := standard_reachable_IPsec_shape prototype ifaces d history checks.noMAC checks.noCarriers
    checks.outboundIPv4 initialized run
  have coherent := standard_reachable_headers prototype ifaces d history processing mode headerBounds
    start finish actions initialized run
  have budget := (standard_reachable_size_budget prototype ifaces d history required mtu plaintextLimit
    authenticationLimit checks emissions processing mode headerBounds initialized run).1
  exact encoded_link_describes_reachable_IPsec_frame codec finish.native.frame root.1 shape
    (originalIP.trans root.2.2.1.symm) (originalEthernet.trans root.2.2.2.symm)
    (by rw [root.2.1]; exact payloadCode) coherent plaintextLimit budget

theorem standard_reachable_link_encoding {S A Key : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (codec : Codec Key) (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    (encoding : ∀ iface frame, prototype.configuration.linkEncoding iface frame = some (linkEncoding codec frame))
    {start finish : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    prototype.configuration.LinkEncodingComplete finish.native := by
  intro path
  exact ⟨linkEncoding codec finish.native.frame, encoding _ _,
    standard_reachable_link_frame_describes prototype ifaces d history codec required mtu plaintextLimit
      authenticationLimit checks emissions processing mode headerBounds initialized run⟩

end TDN.Requirements.StandardDataPlaneBridge
