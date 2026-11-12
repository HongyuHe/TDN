import TDN.Deployments.OuterTunnelNoBypass_BaselineRedSources
import TDN.Requirements.IPsecFlowPolicyChecks

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records LayeredFrame MultiProtocolForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

abbrev records := OuterTunnelNoBypass_BaselineNetwork.records
abbrev entries := OuterTunnelNoBypass_Baseline.entries
abbrev networks := OuterTunnelNoBypass_Baseline.networks
abbrev installations := OuterTunnelNoBypass_Baseline.installations
abbrev expectedEncapStack := OuterTunnelNoBypass_Baseline.expectedEncapStack
abbrev deviceBinding := OuterTunnelNoBypass_Baseline.deviceBinding
abbrev configuration := OuterTunnelNoBypass_Baseline.configuration
abbrev forwarding := OuterTunnelNoBypass_Baseline.redForwarding
abbrev deployment := OuterTunnelNoBypass_Baseline.deployment

deriving instance DecidableEq for Flow
deriving instance DecidableEq for IPsecFlowEndpoints

def capturedConfiguration := directionalConfiguration records installations

load_network_records contexts : List IPsecFlowEndpoints from "../../data/evidence/nestedProtection/BaselineIPsec.json" ["contexts"]

def flows : List Flow := contexts.map IPsecFlowEndpoints.flow

def contextFor (originDomain : Nat) : IPsecFlowEndpoints :=
  (contexts.find? (fun selected => selected.originDomain == originDomain)).getD (contexts.head (by native_decide))

lemma recorded_flow_parameters : ∀ selected ∈ contexts,
    selected.innerStamp.tag = 1 ∧ selected.outerStamp.tag = 2 ∧
    ipsecTunnel records selected.innerStamp = selected.flow.innerTunnel ∧
    ipsecTunnel records selected.outerStamp = selected.flow.outerTunnel := by native_decide

lemma recorded_outgoing_policies : ∀ selected ∈ contexts,
    ∀ iface ∈ records.inventory.ifaces, ∀ policy ∈ capturedConfiguration.ip.egressPolicies iface,
    ∀ association ∈ capturedConfiguration.ip.egressSAs iface, DataPlaneForwarding.saMatchesPolicy association policy →
      (expectedEncapStack iface).head? = some policy.tag → selected.OutgoingPolicy (capturedConfiguration.ip.owner iface) (expectedEncapStack iface) policy association := by
  unfold IPsecFlowEndpoints.OutgoingPolicy IPsecFlowEndpoints.SourceSide IPsecFlowEndpoints.DestinationSide
  native_decide
lemma recorded_incoming_policies : ∀ selected ∈ contexts,
    ∀ iface ∈ records.inventory.ifaces, ∀ policy ∈ capturedConfiguration.ip.ingressPolicies iface,
    ∀ association ∈ capturedConfiguration.ip.ingressSAs iface, DataPlaneForwarding.saMatchesPolicy association policy →
      (expectedEncapStack iface).head? = some policy.tag → selected.IncomingPolicy (capturedConfiguration.ip.owner iface) (expectedEncapStack iface) policy association := by
  unfold IPsecFlowEndpoints.IncomingPolicy IPsecFlowEndpoints.DestinationSide
  native_decide
lemma policy_iface_is_recorded (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy)
    (member : policy ∈ capturedConfiguration.ip.egressPolicies iface ∨ policy ∈ capturedConfiguration.ip.ingressPolicies iface) :
    iface ∈ records.inventory.ifaces := by
  by_contra absent
  have bound : records.nativeIfaces.length ≤ iface := Nat.le_of_not_gt (fun present => absent (List.mem_range.mpr present))
  have missing : records.nativeIfaces[iface]? = none := List.getElem?_eq_none bound
  change policy ∈ (DataPlaneForwarding.deviceAt records.nativeDevices
    (DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner).egressPolicies ∨
    policy ∈ (DataPlaneForwarding.deviceAt records.nativeDevices
      (DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner).ingressPolicies at member
  have empty : (DataPlaneForwarding.deviceAt records.nativeDevices 0).egressPolicies = [] ∧
      (DataPlaneForwarding.deviceAt records.nativeDevices 0).ingressPolicies = [] := by native_decide
  simp only [DataPlaneForwarding.ifaceAt, missing, Option.getD_none] at member
  simp only [show ({} : DataPlaneForwarding.IfaceData).owner = 0 from rfl, empty.1, empty.2,
    List.not_mem_nil, or_self] at member

lemma flow_policy_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (selected : IPsecFlowEndpoints) (member : selected ∈ contexts) :
    IPsecFlowPolicyChecks (deviceBinding primitive) selected expectedEncapStack := by
  have names := recorded_flow_parameters selected member
  refine ⟨names.1, names.2.1, names.2.2.1, names.2.2.2, ?_, ?_⟩
  · intro iface policy association configured installed bound head
    exact recorded_outgoing_policies selected member iface (policy_iface_is_recorded iface policy (Or.inl configured))
      policy configured association installed bound head
  · intro iface policy association configured installed bound head
    exact recorded_incoming_policies selected member iface (policy_iface_is_recorded iface policy (Or.inr configured))
      policy configured association installed bound head

end TDN.Deployments.NestedProtection_Baseline
