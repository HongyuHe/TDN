import TDN.Requirements.EncryptionComponentNoBypassSpec

import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_SampleTrace

import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6_SampleTrace

import TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4_SampleTrace

import TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6_SampleTrace

import TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4_SampleTrace

import TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6_SampleTrace

import TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4_SampleTrace

import TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6_SampleTrace

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000


def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundary_ia_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ia_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundary_ia_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ia_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step4, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step5, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step6, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step7, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step8, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundary_ib_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ib_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundary_ib_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ib_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundary_oa_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_oa_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundary_oa_inbound_tags (by native_decide) (by native_decide)

theorem boundary_oa_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step10, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step11, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step12, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step13, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step14, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    native_decide
def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundary_ob_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by native_decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundary_ob_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundary_ob_inbound_tags (by native_decide) (by native_decide)

theorem boundary_ob_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
  · exact Cslib.LTS.MTr.stepL ⟨witness_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨witness_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    native_decide
end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6
