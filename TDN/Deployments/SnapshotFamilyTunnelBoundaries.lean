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

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6

open DataPlaneForwarding

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Requirements.operationalTunnelBoundary config expectedEncapStack [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ iface, config.owner iface = 5 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 5 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Requirements.BoundaryNoBypass boundaryIA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)

theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Requirements.operationalTunnelBoundary]
    decide

def boundaryIB := Requirements.operationalTunnelBoundary config expectedEncapStack [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ iface, config.owner iface = 6 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).ingressPolicies, a.tag = 1 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 6 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Requirements.BoundaryNoBypass boundaryIB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)

theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .internalProcessing], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Requirements.operationalTunnelBoundary]
    decide

def boundaryOA := Requirements.operationalTunnelBoundary config expectedEncapStack [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ iface, config.owner iface = 7 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 7 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Requirements.BoundaryNoBypass boundaryOA :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)

theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.internalProcessing, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Requirements.operationalTunnelBoundary]
    decide

def boundaryOB := Requirements.operationalTunnelBoundary config expectedEncapStack [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ iface, config.owner iface = 8 →
    ∀ a ∈ config.ingressPolicies iface, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).ingressPolicies, a.tag = 2 := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = 8 at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Requirements.BoundaryNoBypass boundaryOB :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)

theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .internalProcessing], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Requirements.operationalTunnelBoundary]
    decide

end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6
