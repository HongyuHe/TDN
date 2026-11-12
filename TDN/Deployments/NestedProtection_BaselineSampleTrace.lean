import TDN.Deployments.NestedProtection_BaselineSources
import TDN.Deployments.OuterTunnelNoBypass_BaselineSampleTrace

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem snapshot_RG007_ipsec_nonempty_payload_delivered (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∃ start actions finish, (authenticationForwarding primitive).initial start ∧
      (authenticationForwarding primitive).system.MTr start actions finish ∧
      finish.native.datapathStage = .delivered ∧ finish.native.iface = 142 ∧
      finish.native.frame.originDomain = 1 ∧ finish.native.frame.payload ≠ 0 ∧
      finish.native.frame.body.protectionLayers = [] := by
  simpa only [authentication_forwarding_unchanged, OuterTunnelNoBypass_Baseline.interpreted_forwarding_same] using
    OuterTunnelNoBypass_Baseline.snapshot_RG030_baseline_nonempty_payload_delivered primitive

lemma recorded_layer_key_contexts_are_nonempty : ∀ selected ∈ contexts,
    (flowKeyContexts selected).1 ≠ "" ∧ (flowKeyContexts selected).2 ≠ "" := by native_decide

theorem snapshot_RG007_missing_key_independence_rejected (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_nested_layer_protection (authenticationDeployment primitive) (authenticationForwarding primitive) flows
      (fun start _ _ payload => flowAt start payload) (fun _ _ => False) := by
  intro claimed
  have member : (contexts.head (by native_decide)).flow ∈ flows := by native_decide
  have valid := claimed.2.2.1 _ member
  obtain ⟨inner, innerMember, outer, outerMember, innerName, outerName, innerLayer, outerLayer,
    independent, remaining⟩ := valid
  exact independent

def missingAuthority : NestedProtection.PublicAuthenticationBinding :=
  { authenticationBindings.head (by native_decide) with authorityIsCA := false }

lemma missing_ca_authority_is_rejected :
    ¬ missingAuthority.Check "75a63aeafea285095f33115e41f545507ee5492b5df464de35c6b0e9e2ee5615" := by
  unfold NestedProtection.PublicAuthenticationBinding.Check CertificateAuthoritySetting.Check
  native_decide
def swappedInnerTunnel : IPsecFlowEndpoints :=
  let selected := contexts.head (by native_decide)
  { selected with flow := { selected.flow with innerTunnel := selected.flow.outerTunnel } }

set_option synthInstance.maxSize 2048 in
lemma outer_tunnel_cannot_fill_inner_role : ¬ FlowIPsecInventory swappedInnerTunnel := by
  unfold FlowIPsecInventory
  native_decide
end TDN.Deployments.NestedProtection_Baseline
