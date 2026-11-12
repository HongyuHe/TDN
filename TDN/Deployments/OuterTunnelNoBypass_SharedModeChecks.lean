import TDN.Deployments.OuterTunnelNoBypass_SharedIfaceChecks

namespace TDN.Deployments.OuterTunnelNoBypass_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000
set_option maxSynthPendingDepth 256
set_option synthInstance.maxSize 1024

structure TunnelModeBinding where
  tunnel : String
  owner : Nat
  localIface : Nat
  association : DataPlaneForwarding.InstalledSA
  installation : String
  mode : String
  protocol : String
  observation : String
  originalAssociatedIPTunnel : Bool
  interpretedAssociatedIPTunnel : Bool
  sourceHash : String

load_network_records tunnelModeBindings : List TunnelModeBinding from "../../data/evidence/outerTunnelNoBypass/SharedIPsecTunnelBindings.json" ["bindings"]

def TunnelModeBinding.Check (record : TunnelModeBinding) : Prop :=
  record.mode = "tunnel" ∧ record.protocol = "esp" ∧ record.observation ≠ "" ∧ record.sourceHash ≠ "" ∧
  record.originalAssociatedIPTunnel = false ∧ record.interpretedAssociatedIPTunnel = true ∧
  ∃ tunnel ∈ records.tunnels, tunnel.id = record.tunnel ∧ tunnel.mechanism = .ipsec ∧
    tunnel.espTunnelMode = true ∧ tunnel.associatedIPTunnel = record.originalAssociatedIPTunnel ∧
    tunnel.sender = records.componentName record.owner ∧
    ∃ installed ∈ installations, installed.installation.installation = record.installation ∧
      installed.installation.device = record.owner ∧ installed.installation.direction = .outbound ∧
      installed.installation.association = record.association ∧ installed.localIface = record.localIface ∧
      capturedConfiguration.ip.owner record.localIface = record.owner ∧
      record.association ∈ capturedConfiguration.ip.egressSAs record.localIface ∧
      (∃ interface ∈ records.interfaces, interface.device = tunnel.sender ∧
        interface.HasLocalAddress record.association.sender) ∧
      (∃ interface ∈ records.interfaces, interface.device = tunnel.receiver ∧
        interface.HasLocalAddress record.association.receiver) ∧
      ∃ policy ∈ capturedConfiguration.ip.egressPolicies record.localIface,
        DataPlaneForwarding.saMatchesPolicy record.association policy ∧
        records.ifaceName record.localIface ≠ "" ∧
        (tunnel.layer = .inner → policy.tag = 1) ∧ (tunnel.layer = .outer → policy.tag = 2)

instance tunnelModeCheckDecidable (record : TunnelModeBinding) : Decidable record.Check := by
  unfold TunnelModeBinding.Check Interface.HasLocalAddress
  infer_instance

lemma tunnel_mode_bindings_checked : ∀ record ∈ tunnelModeBindings, record.Check := by native_decide

lemma ipsec_tunnels_have_mode_bindings : ∀ tunnel ∈ records.tunnels, tunnel.mechanism = .ipsec →
    ∃ record ∈ tunnelModeBindings, record.tunnel = tunnel.id := by native_decide

def TunnelModeBinding.component (record : TunnelModeBinding) : EncryptionComponentConfiguration :=
  { id := records.componentName record.owner, mechanism := .ipsec,
    espTunnelMode := decide (record.Check ∧ record.mode = "tunnel" ∧ record.protocol = "esp"),
    associatedIPTunnel := decide (record.Check ∧ record.interpretedAssociatedIPTunnel = true),
    outboundMACPolicy := false, inboundMACPolicy := false }

def outerModeBindings : List TunnelModeBinding :=
  tunnelModeBindings.filter (fun record => records.components.any (fun device =>
    device.layer == some .outer && device.id == records.componentName record.owner))

lemma checked_mode_binding_has_component_parameters (record : TunnelModeBinding) (checked : record.Check) :
    record.component.espTunnelMode = true ∧ record.component.associatedIPTunnel = true := by
  constructor
  · exact decide_eq_true_eq.mpr ⟨checked, checked.1, checked.2.1⟩
  · exact decide_eq_true_eq.mpr ⟨checked, checked.2.2.2.2.2.1⟩

lemma tunnel_view_preserves_non_ipsec (tunnel : Tunnel) (other : tunnel.mechanism ≠ .ipsec) :
    associatedIPTunnelView tunnel = tunnel := by simp [associatedIPTunnelView, other]

lemma ipsec_frame_has_bound_outer_header (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (iface : Nat) (before : Frame) (association : DataPlaneForwarding.TunnelSAStamp) :
    (configuration primitive).visibleHeader ((configuration primitive).ipsecFrame iface before association) =
      some { outerHeader association.sender association.receiver "esp" 0 0 with hopLimit := 64 } := by
  simp [Config.visibleHeader, Config.ipsecFrame, configuration, completeConfiguration,
    directionalConfiguration, Records.configuration, Frame.visibleHeader, Frame.pushHeader, Body.visibleHeader]

lemma tunnel_interpretation_is_bound : ∀ tunnel ∈ records.tunnels, tunnel.mechanism = .ipsec →
    ∃ record ∈ tunnelModeBindings, record.tunnel = tunnel.id ∧ record.mode = "tunnel" ∧
      record.protocol = "esp" ∧ record.Check ∧
      (associatedIPTunnelView tunnel).associatedIPTunnel = true ∧
      (associatedIPTunnelView tunnel).sender = tunnel.sender ∧
      (associatedIPTunnelView tunnel).receiver = tunnel.receiver := by
  intro tunnel member mechanism
  obtain ⟨record, recorded, same⟩ := ipsec_tunnels_have_mode_bindings tunnel member mechanism
  have checked := tunnel_mode_bindings_checked record recorded
  exact ⟨record, recorded, same, checked.1, checked.2.1, checked,
    by simp [associatedIPTunnelView, mechanism], by simp [associatedIPTunnelView, mechanism],
    by simp [associatedIPTunnelView, mechanism]⟩

end TDN.Deployments.OuterTunnelNoBypass_Shared
