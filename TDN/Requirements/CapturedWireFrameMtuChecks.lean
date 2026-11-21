import TDN.Requirements.ZoneCrossingLinkSlice

namespace TDN.Requirements.Msc
open Compliance LayeredFrame

def IPFrameChecks (encoded : LinkAdmission.EthernetFrame) (packet : PacketPolicy.Packet)
    (network transport application : List UInt8) : Prop :=
  encoded.Decoded ∧
    (if packet.source < 2^32 then encoded.header.etherType = 2048
     else encoded.header.etherType = 34525) ∧
    encoded.payload = network ++ transport ++ application ∧
    PacketSource.NetworkHeaderMatches packet network (transport.length + application.length) ∧
    PacketSource.TransportHeaderMatches packet transport application

instance (encoded : LinkAdmission.EthernetFrame) (packet : PacketPolicy.Packet)
    (network transport application : List UInt8) :
    Decidable (IPFrameChecks encoded packet network transport application) := by
  unfold IPFrameChecks PacketSource.NetworkHeaderMatches PacketSource.TransportHeaderMatches
  infer_instance

lemma checked_ip_frame_describes_native (encoded : LinkAdmission.EthernetFrame)
    (native : LayeredFrame.TunnelFrame) (actual : PacketPolicy.Packet)
    (visible : native.visibleHeader = some actual)
    (network transport application : List UInt8)
    (checks : IPFrameChecks encoded actual network transport application)
    (payload : native.payload = LinkAdmission.payloadCode application)
    (actualApplication : actual.payloadBytes = some application) : encoded.Describes native := by
  unfold LinkAdmission.EthernetFrame.Describes
  rw [visible]
  refine ⟨checks.1, checks.2.1, network, transport, application, checks.2.2.1,
    checks.2.2.2.1, ?_, Or.inl checks.2.2.2.2⟩
  intro _ _
  exact ⟨actualApplication, payload⟩

lemma checked_macsec_frame_describes_native (encoded : LinkAdmission.EthernetFrame)
    (native : LayeredFrame.TunnelFrame) (association : MacsecAssociation) (inner : Body)
    (body : native.body = .macsec association inner)
    (checks : encoded.DescribesBody (.macsec association inner)) : encoded.Describes native := by
  unfold LinkAdmission.EthernetFrame.Describes TunnelFrame.visibleHeader
  rw [body]
  refine ⟨checks, ?_⟩
  intro header impossible
  cases impossible

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open LayeredFrame

def MACsecFullFrameChecks (encoded : LinkAdmission.EthernetFrame) (association : MacsecAssociation) : Prop :=
  encoded.Decoded ∧ encoded.header.etherType = 35045 ∧
    LinkAdmission.MACsecFraming association encoded.payload ∧
    (PacketSource.field encoded.payload 0 1 / 32 % 2 = 0 →
      encoded.header.source = association.sci / 65536) ∧
    PacketSource.field encoded.payload 0 1 / 8 % 2 = 1

instance (encoded : LinkAdmission.EthernetFrame) (association : MacsecAssociation) :
    Decidable (MACsecFullFrameChecks encoded association) := by
  unfold MACsecFullFrameChecks LinkAdmission.MACsecFraming
  infer_instance

lemma checked_macsec_wire_frame_describes_native (encoded : LinkAdmission.EthernetFrame)
    (native : LayeredFrame.TunnelFrame) (association : MacsecAssociation) (inner : Body)
    (body : native.body = .macsec association inner)
    (checks : MACsecFullFrameChecks encoded association) : encoded.Describes native := by
  apply checked_macsec_frame_describes_native encoded native association inner body
  exact checks

end TDN.Requirements.Msc
