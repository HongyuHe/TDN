import TDN.Targets.MixedTunnelBoundaries

import TDN.Semantics.FiniteMultiProtocolAuthentication

import TDN.Evidence.FreshMixedDeliverySuite

namespace TDN.Imported.PairingIpsecIpsecIntegrated

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [13] [11] 1 5

lemma mixedBoundaryIA_nonempty_attachments :
    ([13] : List Nat) ≠ [] ∧ ([11] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 5).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [13] [11] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState31, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState35, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [16] [14] 1 6

lemma mixedBoundaryIB_nonempty_attachments :
    ([16] : List Nat) ≠ [] ∧ ([14] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 6).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [16] [14] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState31, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState35, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep31, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep34, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [18] [17] 2 7

lemma mixedBoundaryOA_nonempty_attachments :
    ([18] : List Nat) ≠ [] ∧ ([17] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [18] [17] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState26, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState30, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [21] [20] 2 8

lemma mixedBoundaryOB_nonempty_attachments :
    ([21] : List Nat) ≠ [] ∧ ([20] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 8).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [21] [20] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState26, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState30, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingIpsecIpsecIntegrated

namespace TDN.Imported.PairingIpsecMacsecIntegrated

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [11] [9] 1 4

lemma mixedBoundaryIA_nonempty_attachments :
    ([11] : List Nat) ≠ [] ∧ ([9] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 4 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 4).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 4 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [11] [9] 1 4
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState24, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState28, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep24, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep25, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [14] [12] 1 5

lemma mixedBoundaryIB_nonempty_attachments :
    ([14] : List Nat) ≠ [] ∧ ([12] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 5).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [14] [12] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState24, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState28, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep24, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep25, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [16] [15] 2 6

lemma mixedBoundaryOA_nonempty_attachments :
    ([16] : List Nat) ≠ [] ∧ ([15] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 6).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [16] [15] 2 6
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState18, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState23, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep18, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep19, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep20, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep21, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep22, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [20] [19] 2 7

lemma mixedBoundaryOB_nonempty_attachments :
    ([20] : List Nat) ≠ [] ∧ ([19] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [20] [19] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState18, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState23, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep18, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep19, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep20, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep21, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep22, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingIpsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecIntegrated

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [14] [11] 1 5

lemma mixedBoundaryIA_nonempty_attachments :
    ([14] : List Nat) ≠ [] ∧ ([11] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 5).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [14] [11] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState32, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState37, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep34, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep35, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep36, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [18] [15] 1 6

lemma mixedBoundaryIB_nonempty_attachments :
    ([18] : List Nat) ≠ [] ∧ ([15] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 6).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [18] [15] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState32, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState37, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep34, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep35, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep36, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [21] [19] 2 7

lemma mixedBoundaryOA_nonempty_attachments :
    ([21] : List Nat) ≠ [] ∧ ([19] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [21] [19] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState27, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], Reverse.usefulState31, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep29, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep30, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [26] [24] 2 8

lemma mixedBoundaryOB_nonempty_attachments :
    ([26] : List Nat) ≠ [] ∧ ([24] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 8).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [26] [24] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState27, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], Forward.usefulState31, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep29, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep30, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingMacsecIpsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecStandalone

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [24] [21] 1 7

lemma mixedBoundaryIA_nonempty_attachments :
    ([24] : List Nat) ≠ [] ∧ ([21] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [24] [21] 1 7
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState42, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState47, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep42, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep43, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep44, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep45, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep46, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [28] [25] 1 8

lemma mixedBoundaryIB_nonempty_attachments :
    ([28] : List Nat) ≠ [] ∧ ([25] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 8).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [28] [25] 1 8
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState42, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState47, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep42, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep43, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep44, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep45, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep46, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [30] [29] 2 9

lemma mixedBoundaryOA_nonempty_attachments :
    ([30] : List Nat) ≠ [] ∧ ([29] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 9 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 9).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 9 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [30] [29] 2 9
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState32, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState36, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep34, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep35, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [33] [32] 2 10

lemma mixedBoundaryOB_nonempty_attachments :
    ([33] : List Nat) ≠ [] ∧ ([32] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 10 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 10).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 10 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 10 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 10 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [33] [32] 2 10
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState32, [.decryptIPsec, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState36, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep32, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep33, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep34, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep35, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingMacsecIpsecStandalone

namespace TDN.Imported.PairingMacsecMacsecIntegrated

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [12] [9] 1 4

lemma mixedBoundaryIA_nonempty_attachments :
    ([12] : List Nat) ≠ [] ∧ ([9] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 4 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 4).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 4 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [12] [9] 1 4
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState25, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState30, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep25, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [16] [13] 1 5

lemma mixedBoundaryIB_nonempty_attachments :
    ([16] : List Nat) ≠ [] ∧ ([13] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 5).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [16] [13] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState25, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState30, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep25, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep29, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [19] [17] 2 6

lemma mixedBoundaryOA_nonempty_attachments :
    ([19] : List Nat) ≠ [] ∧ ([17] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 6).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [19] [17] 2 6
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState19, [.decryptMACsec, .receive, .inputFilter, .decapsulate, .bridge], Reverse.usefulState24, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep19, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep20, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep21, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep22, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep23, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [25] [23] 2 7

lemma mixedBoundaryOB_nonempty_attachments :
    ([25] : List Nat) ≠ [] ∧ ([23] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [25] [23] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState19, [.decryptMACsec, .receive, .inputFilter, .decapsulate, .bridge], Forward.usefulState24, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep19, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep20, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep21, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep22, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep23, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingMacsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecMacsecStandalone

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [22] [19] 1 6

lemma mixedBoundaryIA_nonempty_attachments :
    ([22] : List Nat) ≠ [] ∧ ([19] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 6).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [22] [19] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState35, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState40, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep35, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep36, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep37, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep38, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep39, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [26] [23] 1 7

lemma mixedBoundaryIB_nonempty_attachments :
    ([26] : List Nat) ≠ [] ∧ ([23] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [26] [23] 1 7
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState35, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState40, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep35, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep36, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep37, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep38, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep39, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [28] [27] 2 8

lemma mixedBoundaryOA_nonempty_attachments :
    ([28] : List Nat) ≠ [] ∧ ([27] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 8).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [28] [27] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState24, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Reverse.usefulState29, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep24, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep25, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [32] [31] 2 9

lemma mixedBoundaryOB_nonempty_attachments :
    ([32] : List Nat) ≠ [] ∧ ([31] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 9 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 9).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 9 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [32] [31] 2 9
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState24, [.decryptMACsec, .receive, .route, .forwardFilter, .passWithoutTransform], Forward.usefulState29, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.usefulStep24, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep25, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.usefulStep28, by decide, by decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingMacsecMacsecStandalone

namespace TDN.Imported.PairingInnerMacsecOuterIpsec

open MultiProtocolExecution LayeredFrame

set_option maxRecDepth 1000000

set_option maxHeartbeats 0

lemma carrier_inbound_checks_1 :
    FiniteCarrierInputChecks devices ifaces carriers 1 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    FiniteCarrierInputChecks devices ifaces carriers 2 := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  finite_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Targets.mixedTunnelBoundary config expectedEncapStack
  [15] [12] 1 5

lemma mixedBoundaryIA_nonempty_attachments :
    ([15] : List Nat) ≠ [] ∧ ([12] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIA_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 5).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [15] [12] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIA_ip_tags mixedBoundaryIA_mac_tags (by decide) (by decide)

theorem mixedBoundaryIA_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨ReverseVLAN0.usefulState26, [.decryptMACsec, .bridge], ReverseVLAN0.usefulState28, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨ReverseVLAN0.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVLAN0.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.refl))
  · simp only [mixedBoundaryIA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryIB := Targets.mixedTunnelBoundary config expectedEncapStack
  [20] [17] 1 6

lemma mixedBoundaryIB_nonempty_attachments :
    ([20] : List Nat) ≠ [] ∧ ([17] : List Nat) ≠ [] := by decide

lemma mixedBoundaryIB_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 6).inbound,
      policy.tag = 1 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryIB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  decide

theorem mixedBoundaryIB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryIB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [20] [17] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixedBoundaryIB_ip_tags mixedBoundaryIB_mac_tags (by decide) (by decide)

theorem mixedBoundaryIB_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨ForwardVLAN0.usefulState26, [.decryptMACsec, .bridge], ForwardVLAN0.usefulState28, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨ForwardVLAN0.usefulStep26, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVLAN0.usefulStep27, by decide, by decide⟩ (Cslib.LTS.MTr.refl))
  · simp only [mixedBoundaryIB, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOA := Targets.mixedTunnelBoundary config expectedEncapStack
  [23] [21] 2 7

lemma mixedBoundaryOA_nonempty_attachments :
    ([23] : List Nat) ≠ [] ∧ ([21] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOA_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 7).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOA_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOA_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOA :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [23] [21] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOA_ip_tags mixedBoundaryOA_mac_tags (by decide) (by decide)

theorem mixedBoundaryOA_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨ReverseVLAN0.usefulState21, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], ReverseVLAN0.usefulState25, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨ReverseVLAN0.usefulStep21, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVLAN0.usefulStep22, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVLAN0.usefulStep23, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVLAN0.usefulStep24, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Targets.mixedTunnelBoundary]
    decide

def mixedBoundaryOB := Targets.mixedTunnelBoundary config expectedEncapStack
  [28] [26] 2 8

lemma mixedBoundaryOB_nonempty_attachments :
    ([28] : List Nat) ≠ [] ∧ ([26] : List Nat) ≠ [] := by decide

lemma mixedBoundaryOB_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices 8).inbound,
      policy.tag = 2 := by decide
  intro entry owner policy member
  change (Execution.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma mixedBoundaryOB_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (Execution.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  decide

theorem mixedBoundaryOB_no_bypass : Targets.BoundaryNoBypass mixedBoundaryOB :=
  Targets.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [28] [26] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixedBoundaryOB_ip_tags mixedBoundaryOB_mac_tags (by decide) (by decide)

theorem mixedBoundaryOB_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨ForwardVLAN0.usefulState21, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], ForwardVLAN0.usefulState25, ?_, ?_, ?_⟩
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide
  · exact Cslib.LTS.MTr.stepL ⟨ForwardVLAN0.usefulStep21, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVLAN0.usefulStep22, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVLAN0.usefulStep23, by decide, by decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVLAN0.usefulStep24, by decide, by decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Targets.mixedTunnelBoundary]
    decide

end TDN.Imported.PairingInnerMacsecOuterIpsec
