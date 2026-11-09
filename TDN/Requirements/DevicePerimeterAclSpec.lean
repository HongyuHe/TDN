import TDN.Requirements.PerimeterInterfaceSlice
import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc
open Compliance

def Device_msc_boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  CoreReq_msc_boundary_interface_filtering d outerFirewallRequired firewallInternal localOuter

end TDN.Requirements.Msc
