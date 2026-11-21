import TDN.Deployments.MtuSizing_DeploymentCoverage

namespace TDN.Deployments.MtuSizing_Records
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel StandardDataPlaneBridge PacketSource


def wireMaterial (installations : List PublicSaRecord) (material : String → IpsecKeyMaterial)
    (wireSeal : DataPlaneForwarding.TunnelSaStamp) : IpsecKeyMaterial :=
  match installations.find? (fun record => record.installation.direction == .outbound &&
    SAWireKey record.installation.association == SealWireKey wireSeal) with
  | some record => material record.materialReference
  | none => material "unlisted-IPsec-material"


def capturedCodec (installations : List PublicSaRecord) (material : String → IpsecKeyMaterial)
    (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSaStamp → IpsecFrameEncoding.Parameters) : IpsecFrameEncoding.Codec IpsecKeyMaterial :=
  { primitive := { primitive with salt := IpsecKeyMaterial.salt },
    key := wireMaterial installations material, parameters := parameters }


def RoleMtuChecks (roles : List SizingRole) : Prop :=
  ∀ role ∈ roles, 1280 ≤ role.mtu ∧ sourceMtu roles role.iface = role.mtu

instance (roles : List SizingRole) : Decidable (RoleMtuChecks roles) := by
  unfold RoleMtuChecks
  infer_instance


theorem source_mtu_minimum (roles : List SizingRole) (checked : RoleMtuChecks roles) :
    ∀ iface, 1280 ≤ sourceMtu roles iface := by
  intro iface
  unfold sourceMtu
  cases selected : roles.find? (fun role => role.iface == iface) with
  | none => simp
  | some role =>
    have member := List.mem_of_find?_eq_some selected
    simpa only [Option.map_some, Option.getD_some] using (checked role member).1

end TDN.Deployments.MtuSizing_Records
