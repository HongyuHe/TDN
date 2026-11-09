import TDN.Deployments.OuterToGray_DeviceModel

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records capturedComponents : List Device from "../../data/evidence/continuation/OuterGraySharedFields.json" ["components"]

load_network_records capturedInterfaces : List Interface from "../../data/evidence/continuation/OuterGraySharedFields.json" ["interfaces"]

load_network_records capturedIfaceNames : List String from "../../data/evidence/continuation/OuterGraySharedFields.json" ["ifaceNames"]

load_network_records capturedOwnerNames : List String from "../../data/evidence/continuation/OuterGraySharedFields.json" ["ownerNames"]

load_network_records capturedPolicies : List InterfacePolicy from "../../data/evidence/continuation/OuterGraySharedFields.json" ["policies"]

load_network_records capturedTunnels : List Tunnel from "../../data/evidence/continuation/OuterGraySharedFields.json" ["tunnels"]

load_network_records capturedPairs : List InnerIPsecPair from "../../data/evidence/continuation/OuterGraySharedFields.json" ["pairs"]

load_network_records capturedMasks : List OwnerMask from "../../data/evidence/continuation/OuterGraySharedFields.json" ["masks"]

load_network_records capturedIpsecSizes : List PacketProcessing.IPsecSizeBinding from "../../data/evidence/continuation/OuterGraySharedFields.json" ["ipsecSizes"]

load_network_records capturedNativeDevices : List DataPlaneForwarding.DeviceData from "../../data/evidence/continuation/OuterGraySharedFields.json" ["nativeDevices"]

load_network_records capturedNativeIfaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/continuation/OuterGraySharedFields.json" ["nativeIfaces"]

load_network_records capturedRoutes : List DataPlaneForwarding.FibRoute from "../../data/evidence/continuation/OuterGraySharedFields.json" ["routes"]

load_network_records capturedLinks : List (Nat × Nat) from "../../data/evidence/continuation/OuterGraySharedFields.json" ["links"]

load_network_records capturedBridges : List (Nat × Nat) from "../../data/evidence/continuation/OuterGraySharedFields.json" ["bridges"]

def records : Records :=
  { components := capturedComponents, interfaces := capturedInterfaces, ifaceNames := capturedIfaceNames, ownerNames := capturedOwnerNames, policies := capturedPolicies, tunnels := capturedTunnels, pairs := capturedPairs, masks := capturedMasks, ipsecSizes := capturedIpsecSizes, nativeDevices := capturedNativeDevices, nativeIfaces := capturedNativeIfaces, routes := capturedRoutes, links := capturedLinks, bridges := capturedBridges }

end TDN.Deployments.OuterToGray_Shared
