import TDN.Deployments.OuterTunnelNoBypass_BaselineNetworkInventoryChecks
import TDN.Deployments.OuterTunnelNoBypass_BaselineNetworkConfigChecks
import TDN.Deployments.OuterTunnelNoBypass_BaselineNetworkMtuChecks

namespace TDN.Deployments.OuterTunnelNoBypass_BaselineNetwork
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge

def codec (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSAStamp → IPsecFrameEncoding.Parameters) :=
  capturedCodec installations material primitive parameters

def deployment (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSAStamp → IPsecFrameEncoding.Parameters) (base : Deployment) :=
  completeDeployment records installations linkPolicies (codec material primitive parameters)
    networks attachments services base

def deviceBinding (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSAStamp → IPsecFrameEncoding.Parameters) :=
  prototype records installations entries roles linkPolicies epoch (codec material primitive parameters) material

end TDN.Deployments.OuterTunnelNoBypass_BaselineNetwork
