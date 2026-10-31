import TDN.Targets.TunnelBoundaries

import TDN.Evidence.FreshFamily444Witness

import TDN.Evidence.FreshFamily446Witness

import TDN.Evidence.FreshFamily464Witness

import TDN.Evidence.FreshFamily466Witness

import TDN.Evidence.FreshFamily644Witness

import TDN.Evidence.FreshFamily646Witness

import TDN.Evidence.FreshFamily664Witness

import TDN.Evidence.FreshFamily666Witness

namespace TDN.Imported.Family444

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family444

namespace TDN.Imported.Family446

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family446

namespace TDN.Imported.Family464

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family464

namespace TDN.Imported.Family466

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family466

namespace TDN.Imported.Family644

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family644

namespace TDN.Imported.Family646

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family646

namespace TDN.Imported.Family664

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family664

namespace TDN.Imported.Family666

open Execution

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

def boundaryIA := Targets.operationalTunnelBoundary config layout [12] [10] 1 5

lemma boundaryIA_inbound_tags : ∀ port, config.owner port = 5 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 5).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 5 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIA_no_bypass : Targets.BoundaryNoBypass boundaryIA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [12] [10] 1 5
    local_stack_conditions boundaryIA_inbound_tags (by decide) (by decide)


theorem boundaryIA_positive_outbound :
    ∃ start actions finish, boundaryIA.outboundEntry start ∧
      boundaryIA.system.MTr start actions finish ∧ boundaryIA.outboundExit finish := by
  refine ⟨witnessState4, [.local, .route, .filter, .encrypt, .route], witnessState9, ?_, ?_, ?_⟩
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep4, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep5, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep6, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep7, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep8, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryIA, Targets.operationalTunnelBoundary]
    decide


def boundaryIB := Targets.operationalTunnelBoundary config layout [15] [13] 1 6

lemma boundaryIB_inbound_tags : ∀ port, config.owner port = 6 →
    ∀ a ∈ config.inbound port, a.tag = 1 := by
  have checked : ∀ a ∈ (deviceAt devices 6).inbound, a.tag = 1 := by decide
  intro port owner a member
  change (portAt ports port).owner = 6 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryIB_no_bypass : Targets.BoundaryNoBypass boundaryIB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [15] [13] 1 6
    local_stack_conditions boundaryIB_inbound_tags (by decide) (by decide)


theorem boundaryIB_positive_inbound :
    ∃ start actions finish, boundaryIB.inboundEntry start ∧
      boundaryIB.system.MTr start actions finish ∧ boundaryIB.inboundExit finish := by
  refine ⟨witnessState31, [.decrypt, .route, .filter, .local], witnessState35, ?_, ?_, ?_⟩
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryIB, Targets.operationalTunnelBoundary]
    decide


def boundaryOA := Targets.operationalTunnelBoundary config layout [17] [16] 2 7

lemma boundaryOA_inbound_tags : ∀ port, config.owner port = 7 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 7).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 7 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOA_no_bypass : Targets.BoundaryNoBypass boundaryOA :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [17] [16] 2 7
    local_stack_conditions boundaryOA_inbound_tags (by decide) (by decide)


theorem boundaryOA_positive_outbound :
    ∃ start actions finish, boundaryOA.outboundEntry start ∧
      boundaryOA.system.MTr start actions finish ∧ boundaryOA.outboundExit finish := by
  refine ⟨witnessState10, [.local, .route, .filter, .encrypt, .route], witnessState15, ?_, ?_, ?_⟩
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep10, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep11, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep12, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep13, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep14, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [boundaryOA, Targets.operationalTunnelBoundary]
    decide


def boundaryOB := Targets.operationalTunnelBoundary config layout [20] [19] 2 8

lemma boundaryOB_inbound_tags : ∀ port, config.owner port = 8 →
    ∀ a ∈ config.inbound port, a.tag = 2 := by
  have checked : ∀ a ∈ (deviceAt devices 8).inbound, a.tag = 2 := by decide
  intro port owner a member
  change (portAt ports port).owner = 8 at owner
  change a ∈ (deviceAt devices (portAt ports port).owner).inbound at member
  rw [owner] at member
  exact checked a member

theorem boundaryOB_no_bypass : Targets.BoundaryNoBypass boundaryOB :=
  Targets.tunnel_boundary_from_local_stack_checks config layout [20] [19] 2 8
    local_stack_conditions boundaryOB_inbound_tags (by decide) (by decide)


theorem boundaryOB_positive_inbound :
    ∃ start actions finish, boundaryOB.inboundEntry start ∧
      boundaryOB.system.MTr start actions finish ∧ boundaryOB.inboundExit finish := by
  refine ⟨witnessState26, [.decrypt, .route, .filter, .local], witnessState30, ?_, ?_, ?_⟩
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨witnessStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨witnessStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [boundaryOB, Targets.operationalTunnelBoundary]
    decide


end TDN.Imported.Family666
