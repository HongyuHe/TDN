import TDN.Deployments.OuterTunnelNoBypass_SharedStackChecks
import TDN.Deployments.OuterTunnelNoBypass_SharedNetwork

namespace TDN.Deployments.OuterTunnelNoBypass_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

abbrev entries := OuterTunnelNoBypass_SharedNetwork.entries
abbrev roles := OuterTunnelNoBypass_SharedNetwork.roles
abbrev networks := OuterTunnelNoBypass_SharedNetwork.networks
abbrev attachments := OuterTunnelNoBypass_SharedNetwork.attachments
abbrev services := OuterTunnelNoBypass_SharedNetwork.services
abbrev epoch := OuterTunnelNoBypass_SharedNetwork.epoch

def material (reference : String) : IPsecKeyMaterial :=
  let index := (installations.map PublicSARecord.materialReference).idxOf reference + 1
  { transform := capturedTransform, encryptionKey := List.replicate 32 (UInt8.ofNat index),
    salt := List.replicate 4 (UInt8.ofNat index), integrityKey := [] }

lemma material_valid : PrivateMaterialAssurance installations material := by
  intro record member
  constructor
  · simp [material, IPsecKeyMaterial.Valid, capturedTransform]
  · rfl

def wireParameters (_ : DataPlaneForwarding.TunnelSAStamp) : IPsecFrameEncoding.Parameters :=
  { sequence := 1, iv := List.replicate 8 0, sequencePositive := by decide,
    sequenceFits := by decide, ivLength := by simp }

def codec (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  OuterTunnelNoBypass_SharedNetwork.codec material primitive wireParameters

def configuration (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  completeConfiguration records installations linkPolicies (codec primitive)

def baseDeployment : Deployment :=
  { devices := [], interfaces := [], tunnels := [], networks := [], centralManagementSite := none,
    networkAttachment := fun _ _ _ => False, policies := [], physicalLink := fun _ _ => False,
    storedVPNKey := fun _ _ => False, certificateAuthenticated := fun _ => false,
    preSharedCAKAuthenticated := fun _ => false, keyManagementCA := fun _ _ => False,
    keyManagementGenerator := fun _ _ => False, innerUsesOuter := fun _ _ => False,
    intendedPeer := fun _ _ => False, policyApproved := fun _ _ => False, aoApproved := fun _ _ => False,
    reachableSource := fun _ _ => False, redService := fun _ _ _ => False,
    grayManagementService := fun _ _ => False, grayWorkstation := fun _ => False,
    standaloneEncapsulator := fun _ => False,
    authority := ⟨fun _ => False, fun _ => False, fun _ => False, fun _ => False,
      fun _ => False, fun _ => False, fun _ => False⟩ }

def deployment (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  OuterTunnelNoBypass_SharedNetwork.deployment material primitive wireParameters baseDeployment

def redNetwork (domain : Nat) : String :=
  ((entries.find? (fun entry => entry.originDomain == domain)).map SourceEntry.network).getD ""

def deviceBinding (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) : DeviceExecutionBinding Unit Unit :=
  { OuterTunnelNoBypass_SharedNetwork.deviceBinding material primitive wireParameters with
    origin := fun domain => .red (redNetwork domain), domainName := redNetwork }

def redForwarding (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  StandardDataPlaneBridge.model (deviceBinding primitive) records.inventory.ifaces (deployment primitive) {}

lemma red_network_of_recorded_origin (domain : Nat) (network : String)
    (origin : sourceOrigin entries records.componentName domain = .red network) : redNetwork domain = network := by
  unfold sourceOrigin at origin
  cases selected : entries.find? (fun entry => entry.originDomain == domain) with
  | some entry => simpa [selected, redNetwork] using origin
  | none =>
    simp only [selected] at origin
    split at origin <;> cases origin

lemma allowed_source_iface (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) (request : PacketSource.Request)
    (allowed : (binding (deviceBinding primitive) records.inventory.ifaces).SourceRequestAllowed (deployment primitive) request) :
    request.iface ∈ records.inventory.ifaces := by
  have entry := allowed.2.2
  change sourceEntry entries request.iface = some (redNetwork request.originDomain) ∧ _ at entry
  obtain ⟨record, member, same, network⟩ := source_entry_is_recorded entries request.iface _ entry.1
  exact List.mem_range.mpr (by simpa only [same] using
    (OuterTunnelNoBypass_SharedNetwork.captured_source_bindings.2.2.1 record member).1)

lemma allowed_source_has_original_red_origin (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (request : PacketSource.Request)
    (allowed : (binding (deviceBinding primitive) records.inventory.ifaces).SourceRequestAllowed (deployment primitive) request) :
    sourceOrigin entries records.componentName request.originDomain = .red (redNetwork request.originDomain) := by
  have source := allowed.2.2
  change sourceEntry entries request.iface = some (redNetwork request.originDomain) ∧ _ at source
  obtain ⟨network, member, name⟩ := source.2
  have names : ∀ network ∈ networks, network.id ≠ "" := by decide
  have nonempty : redNetwork request.originDomain ≠ "" := by rw [← name]; exact names network member
  unfold sourceOrigin
  cases selected : entries.find? (fun entry => entry.originDomain == request.originDomain) with
  | some entry => simp [redNetwork, selected]
  | none => exact False.elim (nonempty (by simp [redNetwork, selected]))

lemma network_sources (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∀ network ∈ (deployment primitive).networks, ∃ request datagrams,
      (binding (deviceBinding primitive) records.inventory.ifaces).SourceRequestAllowed (deployment primitive) request ∧
      request.application ≠ [] ∧ (deviceBinding primitive).origin request.originDomain = .red network.id ∧
      (deviceBinding primitive).sourceProcessing.process request = .emitted datagrams := by
  have original := every_recorded_network_has_source records installations entries roles linkPolicies epoch
    (codec primitive) material networks attachments services baseDeployment OuterTunnelNoBypass_SharedNetwork.flows
    OuterTunnelNoBypass_SharedNetwork.captured_network_sources
  intro network member
  obtain ⟨request, datagrams, allowed, nonempty, red, emitted⟩ := original network member
  have name := red_network_of_recorded_origin request.originDomain network.id red
  refine ⟨request, datagrams, ?_, nonempty, ?_, emitted⟩
  · have source := allowed.2.2
    change (match sourceOrigin entries records.componentName request.originDomain with
      | .red network => _
      | .management component => _
      | .control component protocol => _) at source
    rw [red] at source
    change _ ∧ _ ∧ sourceEntry entries request.iface = some (redNetwork request.originDomain) ∧ _
    rw [name]
    exact ⟨allowed.1, allowed.2.1, source⟩
  · change PayloadOrigin.red (redNetwork request.originDomain) = .red network.id
    rw [name]

lemma static_bindings (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    DeviceDeploymentBindings (deviceBinding primitive) records.inventory.ifaces (deployment primitive) := by
  have original := captured_deployment_bindings records installations entries roles linkPolicies epoch (codec primitive) material
    networks attachments services baseDeployment (OuterTunnelNoBypass_SharedNetwork.captured_structure baseDeployment)
    OuterTunnelNoBypass_SharedNetwork.captured_interface_selection OuterTunnelNoBypass_SharedNetwork.captured_chain_match_conditions
    OuterTunnelNoBypass_SharedNetwork.captured_source_bindings OuterTunnelNoBypass_SharedNetwork.captured_bridge_policies
    (captured_iface_conditions records installations linkPolicies (codec primitive)
      OuterTunnelNoBypass_SharedNetwork.captured_route_egresses OuterTunnelNoBypass_SharedNetwork.captured_physical_endpoints OuterTunnelNoBypass_SharedNetwork.captured_bridge_endpoints)
    OuterTunnelNoBypass_SharedNetwork.captured_sa_inventory_checks OuterTunnelNoBypass_SharedNetwork.captured_tunnels material_valid
    OuterTunnelNoBypass_SharedNetwork.captured_networks_nonempty OuterTunnelNoBypass_SharedNetwork.captured_devices_unique
    OuterTunnelNoBypass_SharedNetwork.captured_interfaces_unique OuterTunnelNoBypass_SharedNetwork.captured_tunnels_unique
  exact ⟨original.processing, original.interfaceLinks, original.linkPolicies, original.headerGeneration,
    original.macsecKeys, original.ipsecKeys, original.redNetworks, original.peers, original.deviceIDs,
    original.interfaceIDs, original.tunnelIDs, original.interfaceIndices, original.ifaceRecords,
    original.physicalLinks, original.sourceEntries, original.macsecTunnels, original.ipsecTunnels⟩

theorem deployment_covered (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    (redForwarding primitive).CoversDeployment (deployment primitive) := by
  have budgets := size_checks_from_captured_records records installations roles linkPolicies (codec primitive)
    OuterTunnelNoBypass_SharedNetwork.captured_size_checks
  apply standard_deployment_covered (deviceBinding primitive) records.inventory.ifaces (deployment primitive) {}
    (static_bindings primitive) (by simp [ObservedHistory.Valid])
    (captured_iface_conditions records installations linkPolicies (codec primitive)
      OuterTunnelNoBypass_SharedNetwork.captured_route_egresses OuterTunnelNoBypass_SharedNetwork.captured_physical_endpoints OuterTunnelNoBypass_SharedNetwork.captured_bridge_endpoints)
    (codec primitive) (requiredSizing roles) (sourceMtu roles) plaintextLimit authenticationLimit
    budgets.1 ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩)
    (fun _ _ => rfl) rfl (source_mtu_minimum roles OuterTunnelNoBypass_SharedNetwork.captured_mtu_checks) rfl
    (allowed_source_iface primitive) (network_sources primitive)

end TDN.Deployments.OuterTunnelNoBypass_Shared
