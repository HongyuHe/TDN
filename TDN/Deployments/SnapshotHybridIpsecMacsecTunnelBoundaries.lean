import TDN.Requirements.HybridIpsecMacsecTunnelBoundaries

import TDN.Models.TableDrivenMultiProtocolAuth

import TDN.Deployments.SnapshotHybridIpsecMacsecDeliverySuite

namespace TDN.Deployments.PairingIpsecIpsecIntegrated

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [13] [11] 1 5

lemma mixed_boundary_ia_nonempty_attachments :
    ([13] : List Nat) ≠ [] ∧ ([11] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 5).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [13] [11] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState31, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState35, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState31, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [16] [14] 1 6

lemma mixed_boundary_ib_nonempty_attachments :
    ([16] : List Nat) ≠ [] ∧ ([14] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 6).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [16] [14] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState31, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState35, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState31, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step31, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [18] [17] 2 7

lemma mixed_boundary_oa_nonempty_attachments :
    ([18] : List Nat) ≠ [] ∧ ([17] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [18] [17] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState26, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState30, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState26, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [21] [20] 2 8

lemma mixed_boundary_ob_nonempty_attachments :
    ([21] : List Nat) ≠ [] ∧ ([20] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 8).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [21] [20] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState26, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState30, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState26, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingIpsecIpsecIntegrated

namespace TDN.Deployments.PairingIpsecMacsecIntegrated

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [11] [9] 1 4

lemma mixed_boundary_ia_nonempty_attachments :
    ([11] : List Nat) ≠ [] ∧ ([9] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 4 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 4).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 4 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [11] [9] 1 4
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState24, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState28, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState24, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step24, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step25, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [14] [12] 1 5

lemma mixed_boundary_ib_nonempty_attachments :
    ([14] : List Nat) ≠ [] ∧ ([12] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 5).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [14] [12] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState24, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState28, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState24, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step24, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step25, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [16] [15] 2 6

lemma mixed_boundary_oa_nonempty_attachments :
    ([16] : List Nat) ≠ [] ∧ ([15] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 6).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [16] [15] 2 6
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState18, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState23, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState18, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step18, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step19, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step20, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step21, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step22, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [20] [19] 2 7

lemma mixed_boundary_ob_nonempty_attachments :
    ([20] : List Nat) ≠ [] ∧ ([19] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [20] [19] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState18, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState23, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState18, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step18, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step19, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step20, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step21, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step22, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingIpsecMacsecIntegrated

namespace TDN.Deployments.PairingMacsecIpsecIntegrated

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [14] [11] 1 5

lemma mixed_boundary_ia_nonempty_attachments :
    ([14] : List Nat) ≠ [] ∧ ([11] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 5).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [14] [11] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState32, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState37, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState32, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step35, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step36, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [18] [15] 1 6

lemma mixed_boundary_ib_nonempty_attachments :
    ([18] : List Nat) ≠ [] ∧ ([15] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 6).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [18] [15] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState32, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState37, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState32, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step35, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step36, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [21] [19] 2 7

lemma mixed_boundary_oa_nonempty_attachments :
    ([21] : List Nat) ≠ [] ∧ ([19] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [21] [19] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState27, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], Reverse.usefulState31, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState27, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step30, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [26] [24] 2 8

lemma mixed_boundary_ob_nonempty_attachments :
    ([26] : List Nat) ≠ [] ∧ ([24] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 8).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [26] [24] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState27, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], Forward.usefulState31, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState27, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step30, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingMacsecIpsecIntegrated

namespace TDN.Deployments.PairingMacsecIpsecStandalone

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [24] [21] 1 7

lemma mixed_boundary_ia_nonempty_attachments :
    ([24] : List Nat) ≠ [] ∧ ([21] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [24] [21] 1 7
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState42, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState47, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState42, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step42, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step43, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step44, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step45, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step46, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [28] [25] 1 8

lemma mixed_boundary_ib_nonempty_attachments :
    ([28] : List Nat) ≠ [] ∧ ([25] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 8).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [28] [25] 1 8
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState42, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState47, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState42, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step42, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step43, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step44, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step45, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step46, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [30] [29] 2 9

lemma mixed_boundary_oa_nonempty_attachments :
    ([30] : List Nat) ≠ [] ∧ ([29] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 9 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 9).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 9 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [30] [29] 2 9
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState32, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState36, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState32, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step35, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [33] [32] 2 10

lemma mixed_boundary_ob_nonempty_attachments :
    ([33] : List Nat) ≠ [] ∧ ([32] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 10 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 10).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 10 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 10 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 10 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [33] [32] 2 10
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState32, [.decryptIPsec, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState36, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState32, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step32, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step33, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step34, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step35, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingMacsecIpsecStandalone

namespace TDN.Deployments.PairingMacsecMacsecIntegrated

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [12] [9] 1 4

lemma mixed_boundary_ia_nonempty_attachments :
    ([12] : List Nat) ≠ [] ∧ ([9] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 4 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 4).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 4 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 4 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [12] [9] 1 4
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState25, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState30, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState25, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step25, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [16] [13] 1 5

lemma mixed_boundary_ib_nonempty_attachments :
    ([16] : List Nat) ≠ [] ∧ ([13] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 5).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [16] [13] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState25, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState30, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState25, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step25, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step29, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [19] [17] 2 6

lemma mixed_boundary_oa_nonempty_attachments :
    ([19] : List Nat) ≠ [] ∧ ([17] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 6).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [19] [17] 2 6
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState19, [.decryptMACsec, .receive, .inputFilter, .decapsulate, .bridge], Reverse.usefulState24, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState19, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step19, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step20, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step21, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step22, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step23, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [25] [23] 2 7

lemma mixed_boundary_ob_nonempty_attachments :
    ([25] : List Nat) ≠ [] ∧ ([23] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [25] [23] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState19, [.decryptMACsec, .receive, .inputFilter, .decapsulate, .bridge], Forward.usefulState24, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState19, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step19, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step20, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step21, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step22, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step23, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingMacsecMacsecIntegrated

namespace TDN.Deployments.PairingMacsecMacsecStandalone

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [22] [19] 1 6

lemma mixed_boundary_ia_nonempty_attachments :
    ([22] : List Nat) ≠ [] ∧ ([19] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 6).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [22] [19] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨Reverse.usefulState35, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState40, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState35, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step35, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step36, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step37, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step38, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step39, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [26] [23] 1 7

lemma mixed_boundary_ib_nonempty_attachments :
    ([26] : List Nat) ≠ [] ∧ ([23] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [26] [23] 1 7
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨Forward.usefulState35, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState40, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState35, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step35, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step36, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step37, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step38, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step39, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [28] [27] 2 8

lemma mixed_boundary_oa_nonempty_attachments :
    ([28] : List Nat) ≠ [] ∧ ([27] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 8).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [28] [27] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨Reverse.usefulState24, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Reverse.usefulState29, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Reverse.usefulState24, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Reverse.useful_step24, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step25, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Reverse.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [32] [31] 2 9

lemma mixed_boundary_ob_nonempty_attachments :
    ([32] : List Nat) ≠ [] ∧ ([31] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 9 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 9).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 9 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 9 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [32] [31] 2 9
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨Forward.usefulState24, [.decryptMACsec, .receive, .route, .forwardFilter, .forwardWithoutEncap], Forward.usefulState29, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [Forward.usefulState24, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨Forward.useful_step24, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step25, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨Forward.useful_step28, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl)))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingMacsecMacsecStandalone

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec

open MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000


lemma carrier_inbound_checks_1 :
    TableDrivenCarrierInputChecks devices ifaces carriers 1 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_1 : CarrierInputCheck config expectedEncapStack 1 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 1
    carrier_inbound_checks_1

lemma carrier_inbound_checks_2 :
    TableDrivenCarrierInputChecks devices ifaces carriers 2 := by
  unfold TableDrivenCarrierInputChecks
  native_decide
lemma carrier_input_preserves_boundary_2 : CarrierInputCheck config expectedEncapStack 2 :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers 2
    carrier_inbound_checks_2

def mixedBoundaryIA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [15] [12] 1 5

lemma mixed_boundary_ia_nonempty_attachments :
    ([15] : List Nat) ≠ [] ∧ ([12] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ia_ip_tags : ∀ entry, config.ip.owner entry = 5 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 5).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 5 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ia_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 5 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ia_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [15] [12] 1 5
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ia_ip_tags mixed_boundary_ia_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ia_positive_inbound :
    ∃ start actions finish, mixedBoundaryIA.inboundEntry start ∧
      mixedBoundaryIA.system.MTr start actions finish ∧ mixedBoundaryIA.inboundExit finish := by
  refine ⟨ReverseVlan0.usefulState26, [.decryptMACsec, .bridge], ReverseVlan0.usefulState28, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [ReverseVlan0.usefulState26, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨ReverseVlan0.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVlan0.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))
  · simp only [mixedBoundaryIA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryIB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [20] [17] 1 6

lemma mixed_boundary_ib_nonempty_attachments :
    ([20] : List Nat) ≠ [] ∧ ([17] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ib_ip_tags : ∀ entry, config.ip.owner entry = 6 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 1 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 6).ingressPolicies,
      policy.tag = 1 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 6 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ib_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 6 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 1
  native_decide
theorem mixed_boundary_ib_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryIB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [20] [17] 1 6
    mixed_local_conditions carrier_input_preserves_boundary_1
    mixed_boundary_ib_ip_tags mixed_boundary_ib_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ib_positive_inbound :
    ∃ start actions finish, mixedBoundaryIB.inboundEntry start ∧
      mixedBoundaryIB.system.MTr start actions finish ∧ mixedBoundaryIB.inboundExit finish := by
  refine ⟨ForwardVlan0.usefulState26, [.decryptMACsec, .bridge], ForwardVlan0.usefulState28, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [ForwardVlan0.usefulState26, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨ForwardVlan0.useful_step26, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVlan0.useful_step27, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))
  · simp only [mixedBoundaryIB, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOA := Requirements.mixedTunnelBoundary config expectedEncapStack
  [23] [21] 2 7

lemma mixed_boundary_oa_nonempty_attachments :
    ([23] : List Nat) ≠ [] ∧ ([21] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_oa_ip_tags : ∀ entry, config.ip.owner entry = 7 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 7).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 7 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_oa_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 7 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_oa_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOA :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [23] [21] 2 7
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_oa_ip_tags mixed_boundary_oa_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_oa_positive_inbound :
    ∃ start actions finish, mixedBoundaryOA.inboundEntry start ∧
      mixedBoundaryOA.system.MTr start actions finish ∧ mixedBoundaryOA.inboundExit finish := by
  refine ⟨ReverseVlan0.usefulState21, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], ReverseVlan0.usefulState25, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [ReverseVlan0.usefulState21, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨ReverseVlan0.useful_step21, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVlan0.useful_step22, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVlan0.useful_step23, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ReverseVlan0.useful_step24, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOA, Requirements.mixedTunnelBoundary]
    native_decide
def mixedBoundaryOB := Requirements.mixedTunnelBoundary config expectedEncapStack
  [28] [26] 2 8

lemma mixed_boundary_ob_nonempty_attachments :
    ([28] : List Nat) ≠ [] ∧ ([26] : List Nat) ≠ [] := by native_decide

lemma mixed_boundary_ob_ip_tags : ∀ entry, config.ip.owner entry = 8 →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = 2 := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices 8).ingressPolicies,
      policy.tag = 2 := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = 8 at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma mixed_boundary_ob_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2 := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = 8 →
    ∀ association ∈ iface.receiveAssociations, association.tag = 2
  native_decide
theorem mixed_boundary_ob_no_bypass : Requirements.BoundaryNoBypass mixedBoundaryOB :=
  Requirements.multi_protocol_tunnel_boundary_from_local_checks config expectedEncapStack [28] [26] 2 8
    mixed_local_conditions carrier_input_preserves_boundary_2
    mixed_boundary_ob_ip_tags mixed_boundary_ob_mac_tags (by native_decide) (by native_decide)

theorem mixed_boundary_ob_positive_inbound :
    ∃ start actions finish, mixedBoundaryOB.inboundEntry start ∧
      mixedBoundaryOB.system.MTr start actions finish ∧ mixedBoundaryOB.inboundExit finish := by
  refine ⟨ForwardVlan0.usefulState21, [.decryptIPsec, .inputFilter, .decapsulate, .bridge], ForwardVlan0.usefulState25, ?_, ?_, ?_⟩
  · refine ⟨rfl, by native_decide, rfl, ?_, rfl⟩
    simp only [ForwardVlan0.usefulState21, MultiProtocolForwarding.CarrierBodies] <;> native_decide
  · exact Cslib.LTS.MTr.stepL ⟨ForwardVlan0.useful_step21, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVlan0.useful_step22, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVlan0.useful_step23, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.stepL ⟨ForwardVlan0.useful_step24, by native_decide, by native_decide⟩ (Cslib.LTS.MTr.refl))))
  · simp only [mixedBoundaryOB, Requirements.mixedTunnelBoundary]
    native_decide
end TDN.Deployments.PairingInnerMacsecOuterIpsec
