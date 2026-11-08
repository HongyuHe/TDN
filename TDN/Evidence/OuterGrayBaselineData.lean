import TDN.Evidence.OuterGrayNativeModel

namespace TDN.Imported.OuterGrayBaseline
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data capturedComponents : List Device from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["components"]

tdn_data capturedInterfaces : List Interface from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["interfaces"]

tdn_data capturedIfaceNames : List String from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["ifaceNames"]

tdn_data capturedOwnerNames : List String from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["ownerNames"]

tdn_data capturedPolicies : List InterfacePolicy from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["policies"]

tdn_data capturedTunnels : List Tunnel from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["tunnels"]

tdn_data capturedPairs : List InnerIPsecPair from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["pairs"]

tdn_data capturedMasks : List OwnerMask from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["masks"]

tdn_data capturedIpsecSizes : List PacketProcessing.IPsecSizeBinding from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["ipsecSizes"]

tdn_data capturedNativeDevices : List Execution.DeviceData from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["nativeDevices"]

tdn_data capturedNativeIfaces : List Execution.IfaceData from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["nativeIfaces"]

tdn_data capturedRoutes : List Execution.Route from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["routes"]

tdn_data capturedLinks : List (Nat × Nat) from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["links"]

tdn_data capturedBridges : List (Nat × Nat) from "../../data/evidence/continuation/OuterGrayBaselineFields.json" ["bridges"]

def records : Records :=
  { components := capturedComponents, interfaces := capturedInterfaces, ifaceNames := capturedIfaceNames, ownerNames := capturedOwnerNames, policies := capturedPolicies, tunnels := capturedTunnels, pairs := capturedPairs, masks := capturedMasks, ipsecSizes := capturedIpsecSizes, nativeDevices := capturedNativeDevices, nativeIfaces := capturedNativeIfaces, routes := capturedRoutes, links := capturedLinks, bridges := capturedBridges }

end TDN.Imported.OuterGrayBaseline
