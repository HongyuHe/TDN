import TDN.Deployments.NestedProtection_MixedTraceData

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def ProtectionMove.Check (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Prop :=
  let header := currentHeader before
  match move.operation with
  | .receive => before.datapathStage = .received ∧ configuration.visibleHeader before.frame = some header
  | .route => (before.datapathStage = .ingress ∨ before.datapathStage = .encapsulated) ∧
      configuration.visibleHeader before.frame = some header ∧
      DataPlaneForwarding.SelectedFibRoute configuration.ip.routes move.route header ∧ move.route.ingress = before.iface
  | .forwardFilter => before.datapathStage = .routed ∧ configuration.visibleHeader before.frame = some header ∧
      DataPlaneForwarding.accepts (configuration.ip.forwardRules before.iface) (configuration.ip.forwardFallback before.iface)
        (policyHeader configuration before header)
  | .forwardWithoutEncap => before.datapathStage = .filtered ∧ configuration.visibleHeader before.frame = some header ∧
      DataPlaneForwarding.lookupSpdPolicies (configuration.ip.egressPolicies before.iface) header = []
  | .encryptIPsec => before.datapathStage = .filtered ∧ configuration.visibleHeader before.frame = some header ∧
      currentPolicy before false ∈ DataPlaneForwarding.lookupSpdPolicies (configuration.ip.egressPolicies before.iface) header ∧
      move.installation.installation.association ∈ configuration.ip.egressSAs before.iface ∧
      DataPlaneForwarding.saMatchesPolicy move.installation.installation.association (currentPolicy before false)
  | .decryptIPsec => before.datapathStage = .received ∧
      before.frame.body = .ipsec ((currentPolicy before true).seal move.installation.installation.association) (bodyContents before.frame.body) ∧
      currentPolicy before true ∈ configuration.ip.ingressPolicies before.iface ∧
      move.installation.installation.association ∈ configuration.ip.ingressSAs before.iface ∧
      DataPlaneForwarding.saMatchesPolicy move.installation.installation.association (currentPolicy before true) ∧
      (bodyContents before.frame.body).visibleHeader =
        some ((bodyContents before.frame.body).visibleHeader.getD header) ∧
      (currentPolicy before true).matches ((bodyContents before.frame.body).visibleHeader.getD header) = true
  | .encryptMACsec => move.macIface ∈ configuration.macIfaces ∧ before.datapathStage = .egressReady ∧
      before.iface = move.macIface.logicalIface ∧ fullMACsecTransmit move.macIface move.transmitted before.frame.body
  | .decryptMACsec => match before.frame.body with
      | .macsec transmitted contents => move.macIface ∈ configuration.macIfaces ∧ before.datapathStage = .received ∧
          before.iface = move.macIface.physicalIface ∧ move.receiveAssociation ∈ move.macIface.receiveAssociations ∧
          SameMACWireIdentity transmitted move.receiveAssociation
      | _ => False
  | .linkTransmit => before.datapathStage = .egressReady ∧ configuration.physicalLink before.iface move.index
  | .bridge => before.datapathStage = .received ∧ configuration.bridge before.iface move.index
  | .inputFilter => before.datapathStage = .ingress ∧ configuration.visibleHeader before.frame = some header ∧
      configuration.ip.localAddress before.iface header.destination ∧
      DataPlaneForwarding.accepts (configuration.ip.inputRules before.iface) (configuration.ip.inputFallback before.iface)
        (policyHeader configuration before header)
  | .deliver => before.datapathStage = .localInput ∧
      before.frame.body = .datagram (before.frame.body.visibleHeader.getD header) ∧
      configuration.ip.ifaceSecurityDomain before.iface = some move.domain
  | _ => False

instance (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Decidable (move.Check before) := by
  unfold ProtectionMove.Check DataPlaneForwarding.accepts fullMACsecTransmit
  cases move.operation <;> dsimp only <;> try infer_instance
  all_goals try { cases before.frame.body <;> dsimp only <;> infer_instance }
  all_goals dsimp only [configuration, Records.configuration]; infer_instance

lemma ProtectionMove.device_step (move : ProtectionMove) (before : MultiProtocolForwarding.State)
    (checked : move.Check before) :
    MultiProtocolForwarding.Step configuration before move.operation (move.after before) := by
  cases operation : move.operation <;> simp only [ProtectionMove.Check, operation] at checked
  all_goals simp only [ProtectionMove.after, operation]
  case receive =>
    exact Step.receive checked.1 checked.2 "new"
  case route =>
    obtain ⟨stage, visible, chosen, entry⟩ := checked
    rcases stage with ingress | encapsulated
    · simpa only [ProtectionMove.after, operation, ingress, reduceCtorEq, ite_false] using
        Step.route move.route ingress visible chosen entry
    · simpa only [ProtectionMove.after, operation, encapsulated, ite_true] using
        Step.routeOuterPacket move.route encapsulated visible chosen entry
  case forwardFilter =>
    exact Step.forwardFilter checked.1 checked.2.1 checked.2.2
  case forwardWithoutEncap =>
    exact Step.forwardWithoutEncap checked.1 checked.2.1 checked.2.2
  case encryptIPsec =>
    exact Step.encryptIPsec (currentPolicy before false) move.installation.installation.association
      checked.1 checked.2.1 checked.2.2.1 checked.2.2.2.1 checked.2.2.2.2
  case decryptIPsec =>
    exact Step.decryptIPsec (currentPolicy before true) move.installation.installation.association
      (bodyContents before.frame.body) ((bodyContents before.frame.body).visibleHeader.getD (currentHeader before))
      checked.1 checked.2.1 checked.2.2.1 checked.2.2.2.1 checked.2.2.2.2.1
      checked.2.2.2.2.2.1 checked.2.2.2.2.2.2 "new"
  case encryptMACsec =>
    exact Step.encryptMACsec move.macIface move.transmitted checked.1 checked.2.1 checked.2.2.1 checked.2.2.2
  case decryptMACsec =>
    cases shape : before.frame.body <;> simp only [shape] at checked
    next transmitted contents =>
      simpa only [ProtectionMove.after, operation, bodyContents, shape] using
        Step.decryptMACsec move.macIface move.receiveAssociation transmitted contents
          checked.1 checked.2.1 checked.2.2.1 shape checked.2.2.2.1 checked.2.2.2.2
  case linkTransmit => exact Step.linkTransmit move.index checked.1 checked.2
  case bridge => exact Step.bridge move.index checked.1 checked.2
  case inputFilter => exact Step.inputFilter checked.1 checked.2.1 checked.2.2.1 checked.2.2.2
  case deliver => exact Step.deliver move.domain checked.1 checked.2.1 checked.2.2

end TDN.Deployments.NestedProtection_Mixed
