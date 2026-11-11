import TDN.Deployments.InnerTunnelNoBypass_IPsecSampleTrace
import TDN.Deployments.InnerTunnelNoBypass_Macsec

namespace TDN.Deployments.InnerTunnelNoBypass_IPsec
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

def unauthenticatedGrayInput : MultiProtocolForwarding.State :=
  { deliveryPath.start with
    initialEntry := false, iface := 73, enteredIface := 69,
    datapathStage := .routed, authenticated := [] }

lemma unauthenticated_gray_input_denied :
    ¬ DataPlaneForwarding.accepts (capturedConfiguration.ip.forwardRules 73)
      (capturedConfiguration.ip.forwardFallback 73)
      (policyHeader { records.configuration with networkBytes := fun body _ => IPsecFrameEncoding.networkLength body }
        unauthenticatedGrayInput deliveryPath.header) := by
  unfold DataPlaneForwarding.accepts
  decide

theorem snapshot_RG029_ipsec_plaintext_gray_input_blocked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ after, (interpretedForwarding primitive).native.AcceptedStep
      unauthenticatedGrayInput .forwardFilter after := by
  rintro ⟨after, accepted⟩
  cases accepted.1 with
  | forwardFilter stage visible permitted =>
    have headerSame := Option.some.inj visible
    change deliveryPath.header = _ at headerSame
    subst headerSame
    exact unauthenticated_gray_input_denied permitted

def uninstalledAssociation : DataPlaneForwarding.InstalledSA :=
  { deliveryPath.association with spi := 0 }

def uninstalledGrayInput : MultiProtocolForwarding.State :=
  { deliveryPath.start with
    initialEntry := false, iface := 69, enteredIface := 69,
    frame := records.configuration.ipsecFrame 57 deliveryPath.start.frame
      (deliveryPath.policy.seal uninstalledAssociation), authenticated := [] }

lemma ingress_association_spi_nonzero :
    ∀ association ∈ capturedConfiguration.ip.ingressSAs 69, association.spi ≠ 0 := by decide

theorem snapshot_RG029_ipsec_uninstalled_spi_blocked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ after, (interpretedForwarding primitive).native.AcceptedStep
      uninstalledGrayInput .decryptIPsec after := by
  rintro ⟨after, accepted⟩
  cases accepted.1 with
  | decryptIPsec policy association body header stage encrypted configured installed bound visible selected tracking =>
    have shape : uninstalledGrayInput.frame.body =
        .ipsec (deliveryPath.policy.seal uninstalledAssociation) deliveryPath.start.frame.body := rfl
    have same := (Body.ipsec.inj (encrypted.symm.trans shape)).1
    have zero := congrArg DataPlaneForwarding.TunnelSAStamp.association same
    change association.spi = 0 at zero
    exact ingress_association_spi_nonzero association installed zero

lemma invalid_observed_binding_disables_component (record : TunnelModeBinding) (invalid : ¬ record.Check) :
    record.component.espTunnelMode = false ∧ record.component.associatedIPTunnel = false := by
  simp [TunnelModeBinding.component, invalid]

def mismatchedModeBinding : TunnelModeBinding :=
  { tunnelModeBindings[0] with
    mode := "transport" }

def mismatchedEndpointBinding : TunnelModeBinding :=
  { tunnelModeBindings[0] with
    association := { tunnelModeBindings[0].association with sender := tunnelModeBindings[0].association.sender + 1 } }

def componentsWithObservedBinding (record : TunnelModeBinding) : List EncryptionComponentConfiguration :=
  components.map (fun component => if component.id = record.component.id then record.component else component)

lemma mismatched_mode_binding_is_rejected : ¬ mismatchedModeBinding.Check := by decide

lemma mismatched_endpoint_binding_is_rejected : ¬ mismatchedEndpointBinding.Check := by decide

theorem snapshot_RG029_observed_mode_mismatch_blocks_application (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_inner_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive)
      (componentsWithObservedBinding mismatchedModeBinding) false false := by
  intro accepted
  have member : mismatchedModeBinding.component ∈ componentsWithObservedBinding mismatchedModeBinding := by
    change mismatchedModeBinding.component ∈ mismatchedModeBinding.component :: _
    exact List.mem_cons_self
  have enabled := (accepted.2.2 mismatchedModeBinding.component member (Or.inl rfl)).1 rfl
  have disabled := (invalid_observed_binding_disables_component _ mismatched_mode_binding_is_rejected).1
  rw [disabled] at enabled
  cases enabled.1

theorem snapshot_RG029_observed_endpoint_mismatch_blocks_application (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_inner_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive)
      (componentsWithObservedBinding mismatchedEndpointBinding) false false := by
  intro accepted
  have member : mismatchedEndpointBinding.component ∈ componentsWithObservedBinding mismatchedEndpointBinding := by
    change mismatchedEndpointBinding.component ∈ mismatchedEndpointBinding.component :: _
    exact List.mem_cons_self
  have enabled := (accepted.2.2 mismatchedEndpointBinding.component member (Or.inl rfl)).1 rfl
  have disabled := (invalid_observed_binding_disables_component _ mismatched_endpoint_binding_is_rejected).1
  rw [disabled] at enabled
  cases enabled.1

end TDN.Deployments.InnerTunnelNoBypass_IPsec

namespace TDN.Deployments.InnerTunnelNoBypass_Macsec
open Compliance Requirements Requirements.Msc

lemma outbound_mac_objective_has_unconfigured_component :
    ∃ component ∈ components, deployment.Relevant component.id ∧ component.outboundMACPolicy = false := by
  unfold Deployment.Relevant
  decide

lemma inbound_mac_objective_has_unconfigured_component :
    ∃ component ∈ components, deployment.Relevant component.id ∧ component.inboundMACPolicy = false := by
  unfold Deployment.Relevant
  decide

theorem snapshot_RG029_outbound_mac_objective_rejects_missing_policy :
    ¬ msc_inner_tunnel_no_bypass deployment forwarding components true false := by
  intro accepted
  obtain ⟨component, member, relevant, disabled⟩ := outbound_mac_objective_has_unconfigured_component
  have enabled := (accepted.2.2 component member relevant).2.1 rfl
  rw [disabled] at enabled
  cases enabled

theorem snapshot_RG029_inbound_mac_objective_rejects_missing_policy :
    ¬ msc_inner_tunnel_no_bypass deployment forwarding components false true := by
  intro accepted
  obtain ⟨component, member, relevant, disabled⟩ := inbound_mac_objective_has_unconfigured_component
  have enabled := (accepted.2.2 component member relevant).2.2 rfl
  rw [disabled] at enabled
  cases enabled

end TDN.Deployments.InnerTunnelNoBypass_Macsec
