import TDN.Deployments.OuterTunnelNoBypass_SharedNetworkInventoryChecks
import TDN.Deployments.OuterTunnelNoBypass_SharedNetworkConfigChecks
import TDN.Deployments.OuterTunnelNoBypass_SharedNetworkMtuChecks

namespace TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge

def codec (material : String → IpsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSaStamp → IpsecFrameEncoding.Parameters) :=
  capturedCodec installations material primitive parameters

def deployment (material : String → IpsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSaStamp → IpsecFrameEncoding.Parameters) (base : Deployment) :=
  completeDeployment records installations linkPolicies (codec material primitive parameters)
    networks attachments services base

def deviceBinding (material : String → IpsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSaStamp → IpsecFrameEncoding.Parameters) :=
  prototype records installations entries roles linkPolicies epoch (codec material primitive parameters) material

end TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
