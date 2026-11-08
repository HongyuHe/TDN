import TDN.Evidence.BoundaryNativeModel

namespace TDN.Imported.GrayFirewallShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data capturedComponents : List Device from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["components"]

tdn_data capturedInterfaces : List Interface from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["interfaces"]

tdn_data capturedIfaceNames : List String from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["ifaceNames"]

tdn_data capturedOwnerNames : List String from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["ownerNames"]

tdn_data capturedPolicies : List InterfacePolicy from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["policies"]

tdn_data capturedTunnels : List Tunnel from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["tunnels"]

tdn_data capturedPairs : List InnerIPsecPair from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["pairs"]

tdn_data capturedMasks : List OwnerMask from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["masks"]

tdn_data capturedIpsecSizes : List PacketProcessing.IPsecSizeBinding from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["ipsecSizes"]

tdn_data capturedNativeDevices : List Execution.DeviceData from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["nativeDevices"]

tdn_data capturedNativeIfaces : List Execution.IfaceData from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["nativeIfaces"]

tdn_data capturedRoutes : List Execution.Route from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["routes"]

tdn_data capturedLinks : List (Nat × Nat) from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["links"]

tdn_data capturedBridges : List (Nat × Nat) from "../../data/evidence/continuation/GrayFirewallSharedFields.json" ["bridges"]

def records : Records :=
  { components := capturedComponents, interfaces := capturedInterfaces, ifaceNames := capturedIfaceNames, ownerNames := capturedOwnerNames, policies := capturedPolicies, tunnels := capturedTunnels, pairs := capturedPairs, masks := capturedMasks, ipsecSizes := capturedIpsecSizes, nativeDevices := capturedNativeDevices, nativeIfaces := capturedNativeIfaces, routes := capturedRoutes, links := capturedLinks, bridges := capturedBridges }
tdn_data services : List ServiceRegistration from "../../data/evidence/continuation/GrayFirewallShared.json" ["services"]
tdn_data redEndpoints : List RedServiceEndpoint from "../../data/evidence/continuation/GrayFirewallShared.json" ["redEndpoints"]
tdn_data peers : List BoundaryPeer from "../../data/evidence/continuation/GrayFirewallShared.json" ["peers"]
tdn_data firewalls : List FirewallBinding from "../../data/evidence/continuation/GrayFirewallShared.json" ["firewalls"]
tdn_data firewallInternal : List String from "../../data/evidence/continuation/GrayFirewallShared.json" ["firewallInternal"]

tdn_data controls : List BoundaryControlFlow from "../../data/evidence/continuation/GrayFirewallShared.json" ["controls"]

def deployment (base : Deployment) : Deployment :=
  registeredDeployment records services redEndpoints base controls

end TDN.Imported.GrayFirewallShared
