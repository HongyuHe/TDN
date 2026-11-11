import TDN.Deployments.NestedProtection_MixedData

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma route_owners : ∀ route ∈ records.routes,
    (DataPlaneForwarding.ifaceAt records.ifaceData route.egress).owner =
      (DataPlaneForwarding.ifaceAt records.ifaceData route.ingress).owner := by decide

lemma physical_stacks : ∀ edge ∈ records.links,
    expectedEncapStack edge.1 = expectedEncapStack edge.2 := by decide

lemma bridge_stacks : ∀ edge ∈ records.bridges,
    expectedEncapStack edge.1 = expectedEncapStack edge.2 := by decide

lemma forward_defaults : ∀ device ∈ ({} : DataPlaneForwarding.DeviceData) :: records.deviceData,
    device.forwardFallback = .deny := by decide

lemma forward_rules : DataPlaneForwarding.TableDrivenRoutedForwardChecks records.deviceData records.ifaceData records.routes := by
  unfold DataPlaneForwarding.TableDrivenRoutedForwardChecks
  decide

lemma output_rules : DataPlaneForwarding.TableDrivenOutputChecks records.deviceData records.ifaceData := by
  unfold DataPlaneForwarding.TableDrivenOutputChecks
  decide

lemma outer_routes : DataPlaneForwarding.TableDrivenOuterRoutes records.deviceData records.ifaceData records.routes := by
  unfold DataPlaneForwarding.TableDrivenOuterRoutes
  decide

lemma table_stack_conditions : DataPlaneForwarding.PerHopEncapConditions
    (DataPlaneForwarding.dataPlaneModelFromRecords records.deviceData records.ifaceData records.routes records.links [])
    expectedEncapStack :=
  DataPlaneForwarding.local_stack_conditions_of_routed_finite_checks records.deviceData records.ifaceData
    records.routes records.links [] route_owners physical_stacks (by simp) forward_defaults forward_rules output_rules outer_routes

lemma headered_stack_conditions : HeaderedLocalConditions configuration expectedEncapStack := by
  refine ⟨rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨table_stack_conditions.routeOwner, table_stack_conditions.link, table_stack_conditions.bridge,
      table_stack_conditions.forward, table_stack_conditions.output, table_stack_conditions.routeOuterPacket⟩
  · intro first last linked
    exact physical_stacks (first,last) linked
  · intro first last connected
    exact bridge_stacks (first,last) connected
  · have checked : ∀ iface ∈ records.macIfaces, MACTransmitCheck records.ifaceData iface := by decide
    intro iface member association installed
    have fact := checked iface member
    simpa only [MACTransmitCheck, installed, expectedEncapStack] using fact
  · decide
  · have checked : ∀ sender ∈ records.macIfaces,
        ∀ transmitted ∈ sender.transmitAssociation.toList, ∀ receiver ∈ records.macIfaces,
        ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
          transmitted.tag = association.tag := by decide
    intro sender member transmitted installed receiver present association received same
    exact checked sender member transmitted (by simp [installed]) receiver present association received same
  · decide
  all_goals simp [withoutHeaderProcessing, Records.configuration, dataPlaneModelFromRecords]

lemma recorded_flow_parameters : ∀ selected ∈ contexts,
    selected.innerStamp.tag = 1 ∧ selected.outerAssociation.tag = 2 ∧
    records.ipsecTunnel selected.innerStamp = selected.flow.innerTunnel ∧
    records.macsecTunnel selected.outerAssociation = selected.flow.outerTunnel := by decide

lemma recorded_outgoing_policies : ∀ selected ∈ contexts,
    ∀ iface ∈ ifaces, ∀ policy ∈ configuration.ip.egressPolicies iface,
    ∀ association ∈ configuration.ip.egressSAs iface, DataPlaneForwarding.saMatchesPolicy association policy →
      (expectedEncapStack iface).head? = some policy.tag →
      selected.OutgoingPolicy (configuration.ip.owner iface) (expectedEncapStack iface) policy association := by
  unfold MixedFlowEndpoints.OutgoingPolicy MixedFlowEndpoints.SourceSide MixedFlowEndpoints.DestinationSide
  decide

lemma recorded_incoming_policies : ∀ selected ∈ contexts,
    ∀ iface ∈ ifaces, ∀ policy ∈ configuration.ip.ingressPolicies iface,
    ∀ association ∈ configuration.ip.ingressSAs iface, DataPlaneForwarding.saMatchesPolicy association policy →
      (expectedEncapStack iface).head? = some policy.tag →
      selected.IncomingPolicy (configuration.ip.owner iface) (expectedEncapStack iface) policy association := by
  unfold MixedFlowEndpoints.IncomingPolicy MixedFlowEndpoints.DestinationSide
  decide

lemma policy_iface_is_recorded (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy)
    (member : policy ∈ configuration.ip.egressPolicies iface ∨ policy ∈ configuration.ip.ingressPolicies iface) :
    iface ∈ ifaces := by
  by_contra absent
  have absentRange : iface = 0 ∨ records.ifaceData.length ≤ iface := by
    have fact : ¬ (iface < records.ifaceData.length ∧ iface ≠ 0) := by
      intro present
      apply absent
      simpa only [Records.ifaces, List.mem_filter, List.mem_range, bne_iff_ne] using present
    omega
  have ownerZero : configuration.ip.owner iface = 0 := by
    rcases absentRange with rfl | outside
    · rfl
    · have missing : records.ifaceData[iface]? = none := List.getElem?_eq_none outside
      change (DataPlaneForwarding.ifaceAt records.ifaceData iface).owner = 0
      simp only [DataPlaneForwarding.ifaceAt, missing, Option.getD_none]
  have empty : (DataPlaneForwarding.deviceAt records.deviceData 0).egressPolicies = [] ∧
      (DataPlaneForwarding.deviceAt records.deviceData 0).ingressPolicies = [] := by decide
  change policy ∈ (DataPlaneForwarding.deviceAt records.deviceData (configuration.ip.owner iface)).egressPolicies ∨
    policy ∈ (DataPlaneForwarding.deviceAt records.deviceData (configuration.ip.owner iface)).ingressPolicies at member
  simp only [ownerZero, empty.1, empty.2, List.not_mem_nil, or_self] at member

lemma flow_policy_checks (selected : MixedFlowEndpoints) (member : selected ∈ contexts) :
    MixedFlowPolicyChecks deviceBinding selected expectedEncapStack := by
  have names := recorded_flow_parameters selected member
  refine ⟨names.1, names.2.1, names.2.2.1, names.2.2.2, ?_, ?_, ?_, ?_, ?_⟩
  · intro iface policy association configured installed bound head
    exact recorded_outgoing_policies selected member iface (policy_iface_is_recorded iface policy (Or.inl configured))
      policy configured association installed bound head
  · intro iface policy association configured installed bound head
    exact recorded_incoming_policies selected member iface (policy_iface_is_recorded iface policy (Or.inr configured))
      policy configured association installed bound head
  · have checked : ∀ selected ∈ contexts, ∀ route ∈ records.routes,
        route.egress = selected.destinationLogicalIface → selected.innerStamp.receiver < route.destPrefixLow ∨
          route.destPrefixHigh < selected.innerStamp.receiver := by decide
    exact checked selected member
  · have checked : ∀ selected ∈ contexts, ∀ iface ∈ records.macIfaces,
        ∀ association ∈ iface.transmitAssociation.toList,
        iface.logicalIface = selected.destinationLogicalIface ∨ association = selected.outerAssociation := by decide
    intro iface configured association installed
    exact checked selected member iface configured association (by simp [installed])
  · decide

end TDN.Deployments.NestedProtection_Mixed
