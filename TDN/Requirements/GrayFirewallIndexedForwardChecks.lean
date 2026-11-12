import TDN.Requirements.GrayFirewallIptablesPatterns

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules MultiProtocolForwarding

def GrayIndexedForwardChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (pairs : List InnerIPsecPair) (candidates : Nat → List DataPlaneForwarding.FibRoute)
    (aclCheck : Interface → Direction → PacketPolicy.AclFlowSelector → Bool) (interface : Interface) (direction : Direction) : Prop :=
  ∀ record ∈ pairs, ∀ route ∈ candidates record.endpoints.destinationAddress,
    (if direction = .inbound then inventory.ifaceName route.ingress = interface.id
      else inventory.ifaceName route.egress = interface.id) →
    route.ingress ∈ inventory.ifaces → route.egress ∈ inventory.ifaces →
    GrayIncomingSource d inventory interface.device route.ingress record.endpoints.sourceAddress →
    ∀ form ∈ PacketPolicy.IPsecForm.all,
      aclCheck interface direction (form.maskWithOptions record.endpoints.sourceAddress record.endpoints.destinationAddress
        (inventory.configuration.ip.interfaceName route.ingress)
        (inventory.configuration.ip.interfaceName route.egress) []
        ((DataPlaneForwarding.lookupSpdPolicies (inventory.configuration.ip.egressPolicies route.egress)
          (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
            DataPlaneForwarding.IpsecPolicy.id) (interface.mtu.getD 0)) = true

set_option synthInstance.maxSize 2048 in
instance (d : Deployment) (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (candidates : Nat → List DataPlaneForwarding.FibRoute)
    (aclCheck : Interface → Direction → PacketPolicy.AclFlowSelector → Bool) (interface : Interface) (direction : Direction)
    [∀ name, DecidablePred (d.reachableSource name)] :
    Decidable (GrayIndexedForwardChecks d inventory pairs candidates aclCheck interface direction) := by
  unfold GrayIndexedForwardChecks
  infer_instance


theorem gray_forward_checks_from_route_certificates (d : Deployment)
    (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (candidates : Nat → List DataPlaneForwarding.FibRoute)
    (coverage : ∀ record ∈ pairs, ∀ route,
      DataPlaneForwarding.SelectedFibRoute inventory.configuration.ip.routes route
        (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
      route ∈ candidates record.endpoints.destinationAddress)
    (aclCheck : Interface → Direction → PacketPolicy.AclFlowSelector → Bool)
    (interface : Interface) (direction : Direction)
    (sound : ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.direction = direction → policy.hook = .forward →
      ∀ mask, aclCheck interface direction mask = true → mask.IsPermittedByAclChain policy.rules)
    (checked : GrayIndexedForwardChecks d inventory pairs candidates aclCheck interface direction) :
    GrayForwardChecks d inventory pairs interface direction := by
  intro record member route _ name ingress egress selected source form formMember policy policyMember policyName policyDirection policyHook
  apply sound policy policyMember policyName policyDirection policyHook
  exact checked record member route (coverage record member route selected) name ingress egress source
    form formMember

end TDN.Requirements.Msc
