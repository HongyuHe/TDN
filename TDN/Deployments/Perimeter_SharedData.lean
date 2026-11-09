import TDN.Deployments.Perimeter_DeviceModel

namespace TDN.Deployments.Perimeter_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records capturedComponents : List Device from "../../data/evidence/continuation/BoundarySharedFields.json" ["components"]

load_network_records capturedInterfaces : List Interface from "../../data/evidence/continuation/BoundarySharedFields.json" ["interfaces"]

load_network_records capturedIfaceNames : List String from "../../data/evidence/continuation/BoundarySharedFields.json" ["ifaceNames"]

load_network_records capturedOwnerNames : List String from "../../data/evidence/continuation/BoundarySharedFields.json" ["ownerNames"]

load_network_records capturedPolicies : List InterfacePolicy from "../../data/evidence/continuation/BoundarySharedFields.json" ["policies"]

load_network_records capturedTunnels : List Tunnel from "../../data/evidence/continuation/BoundarySharedFields.json" ["tunnels"]

load_network_records capturedPairs : List InnerIPsecPair from "../../data/evidence/continuation/BoundarySharedFields.json" ["pairs"]

load_network_records capturedMasks : List OwnerMask from "../../data/evidence/continuation/BoundarySharedFields.json" ["masks"]

load_network_records capturedIpsecSizes : List PacketProcessing.IPsecSizeBinding from "../../data/evidence/continuation/BoundarySharedFields.json" ["ipsecSizes"]

load_network_records capturedNativeDevices : List DataPlaneForwarding.DeviceData from "../../data/evidence/continuation/BoundarySharedFields.json" ["nativeDevices"]

load_network_records capturedNativeIfaces : List DataPlaneForwarding.IfaceData from "../../data/evidence/continuation/BoundarySharedFields.json" ["nativeIfaces"]

load_network_records capturedRoutes : List DataPlaneForwarding.FibRoute from "../../data/evidence/continuation/BoundarySharedFields.json" ["routes"]

load_network_records capturedLinks : List (Nat × Nat) from "../../data/evidence/continuation/BoundarySharedFields.json" ["links"]

load_network_records capturedBridges : List (Nat × Nat) from "../../data/evidence/continuation/BoundarySharedFields.json" ["bridges"]

def records : Records :=
  { components := capturedComponents, interfaces := capturedInterfaces, ifaceNames := capturedIfaceNames, ownerNames := capturedOwnerNames, policies := capturedPolicies, tunnels := capturedTunnels, pairs := capturedPairs, masks := capturedMasks, ipsecSizes := capturedIpsecSizes, nativeDevices := capturedNativeDevices, nativeIfaces := capturedNativeIfaces, routes := capturedRoutes, links := capturedLinks, bridges := capturedBridges }
load_network_records services : List ServiceRegistration from "../../data/evidence/continuation/Perimeter_Shared.json" ["services"]
load_network_records redEndpoints : List RedServiceEndpoint from "../../data/evidence/continuation/Perimeter_Shared.json" ["redEndpoints"]
load_network_records peers : List BoundaryPeer from "../../data/evidence/continuation/Perimeter_Shared.json" ["peers"]
load_network_records firewalls : List FirewallBinding from "../../data/evidence/continuation/Perimeter_Shared.json" ["firewalls"]
load_network_records firewallInternal : List String from "../../data/evidence/continuation/Perimeter_Shared.json" ["firewallInternal"]

load_network_records controls : List BoundaryControlFlow from "../../data/evidence/continuation/Perimeter_Shared.json" ["controls"]

def deployment (base : Deployment) : Deployment :=
  registeredDeployment records services redEndpoints base controls

end TDN.Deployments.Perimeter_Shared
