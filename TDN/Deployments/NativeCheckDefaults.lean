import TDN.Import.NativeDecide
import TDN.Requirements.MscComplianceSchema

/-! A closed representative for deployment fields that a concrete check does not use.
`close_check_with` checks definitional equality with the original parameterized goal.
Changing a field that affects the obligation therefore fails rather than specializing it. -/

namespace TDN.Deployments

def emptyDeploymentForChecks : Compliance.Deployment :=
  { devices := [], interfaces := [], tunnels := [], networks := [], centralManagementSite := none,
    networkAttachment := fun _ _ _ => False, policies := [], physicalLink := fun _ _ => False,
    storedVPNKey := fun _ _ => False, certificateAuthenticated := fun _ => false,
    preSharedCAKAuthenticated := fun _ => false, keyManagementCA := fun _ _ => False,
    keyManagementGenerator := fun _ _ => False, innerUsesOuter := fun _ _ => False,
    intendedPeer := fun _ _ => False, policyApproved := fun _ _ => False, aoApproved := fun _ _ => False,
    reachableSource := fun _ _ => False, redService := fun _ _ _ => False,
    grayManagementService := fun _ _ => False, grayWorkstation := fun _ => False,
    standaloneEncapsulator := fun _ => False,
    authority := ⟨fun _ => False, fun _ => False, fun _ => False, fun _ => False,
      fun _ => False, fun _ => False, fun _ => False⟩ }

def emptyInventoryForChecks : PacketProcessing.Inventory :=
  { ifaces := [], ifaceName := fun _ => "", componentName := fun _ => "",
    mkaPeers := [], macsecTunnel := fun _ => "",
    configuration :=
      { ip :=
          { routes := [], forwardRules := fun _ => [], inputRules := fun _ => [],
            outputRules := fun _ => [], forwardFallback := fun _ => .deny,
            inputFallback := fun _ => .deny, outputFallback := fun _ => .deny,
            egressPolicies := fun _ => [], ingressPolicies := fun _ => [],
            egressSAs := fun _ => [], ingressSAs := fun _ => [],
            interfaceName := fun _ => "", owner := fun _ => 0,
            link := fun _ _ => False, bridging := fun _ _ _ => False,
            localAddress := fun _ _ => False, ifaceSecurityDomain := fun _ => none,
            canOriginateTraffic := fun _ => False },
        macIfaces := [], carriers := [], bridge := fun _ _ => False,
        physicalLink := fun _ _ => False } }

end TDN.Deployments
