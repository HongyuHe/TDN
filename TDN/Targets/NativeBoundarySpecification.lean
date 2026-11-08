import TDN.Targets.BoundaryView
import TDN.Targets.CompleteSpecifications

namespace TDN.Targets.Complete
open Compliance

def Native_msc_boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  Primitive_msc_boundary_interface_filtering d outerFirewallRequired firewallInternal localOuter

end TDN.Targets.Complete
