import TDN.Requirements.CsfcRoleObligations

namespace TDN.Requirements.Msc
open Compliance

def nested_layer_protection {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (flows : List Flow) (flowOf : S → List A → S → PayloadId → Flow) (independentKeys : String → String → Prop) : Prop :=
  scoped_nested_layer_protection { d with deviceScope := none } model flows flowOf independentKeys

def security_level_connectivity {S A : Type} (context : ComplianceContext S A) : Prop :=
  scoped_security_level_connectivity { context.deployment with deviceScope := none } context.model
    context.authenticatedInnerPairs context.establishedInnerTunnels context.requiredConnectivity
    context.includedUnclassified ∧
  (∃ contexts, context ∈ contexts ∧ ReferencesClosed contexts) ∧
  ∀ network ∈ context.includedUnclassified, context.AllApplicableDuties (.enclaveNetwork network)

def gray_firewall_path_coverage (d : Deployment) (topology : GrayTopology) : Prop :=
  scoped_gray_firewall_path_coverage { d with deviceScope := none } topology

def inner_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  scoped_inner_tunnel_no_bypass { d with deviceScope := none } model components
    outboundMACObjective inboundMACObjective

def outer_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  scoped_outer_tunnel_no_bypass { d with deviceScope := none } model components
    outboundMACObjective inboundMACObjective

def outer_firewall_placement := @TDN.Requirements.graph_outer_firewall_placement

def boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  scoped_boundary_interface_filtering { d with deviceScope := none } outerFirewallRequired
    firewallInternal localOuter

def ip_header_and_multicast_filtering (d : Deployment)
    (dropIPv4OptionsObjective : String → Bool) : Prop :=
  scoped_ip_header_and_multicast_filtering { d with deviceScope := none } dropIPv4OptionsObjective

def outer_gray_interface_policy (d : Deployment) (cdpOnGray : Bool) : Prop :=
  scoped_outer_gray_interface_policy { d with deviceScope := none } cdpOnGray

def gray_firewall_allowlist (d : Deployment) (grayFirewallRequired : Bool) : Prop :=
  scoped_gray_firewall_allowlist { d with deviceScope := none } grayFirewallRequired

end TDN.Requirements.Msc
