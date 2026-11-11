import TDN.Deployments.NestedProtection_BaselineFlowData
import TDN.Deployments.NestedProtection_AuthenticationRecords

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records NestedProtection StandardDataPlaneBridge

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records authenticationBindings : List PublicAuthenticationBinding from
  "../../data/evidence/nestedProtection/BaselineIPsec.json" ["authenticationBindings"]
load_network_records innerOuterUses : List (String × String) from
  "../../data/evidence/nestedProtection/BaselineIPsec.json" ["innerOuterUses"]

deriving instance DecidableEq for Device
deriving instance DecidableEq for Tunnel

def authenticationSettings := authenticationBindings.map PublicAuthenticationBinding.setting

def authenticationDeployment (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) : Deployment :=
  { certificateAuthorityView authenticationSettings (deployment primitive) with
    innerUsesOuter := fun inner outer => (inner, outer) ∈ innerOuterUses }

def authenticationForwarding (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  StandardDataPlaneBridge.model (deviceBinding primitive) records.inventory.ifaces (authenticationDeployment primitive) {}

lemma authentication_forwarding_unchanged (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    authenticationForwarding primitive = forwarding primitive := rfl

lemma recorded_authentication_checks : ∀ record ∈ authenticationBindings,
    record.Check "75a63aeafea285095f33115e41f545507ee5492b5df464de35c6b0e9e2ee5615" := by
  unfold PublicAuthenticationBinding.Check CertificateAuthoritySetting.Check
  decide

lemma recorded_authentication_coverage :
    (∀ component ∈ records.components, component.layer = some .inner ∨ component.layer = some .outer →
      ∃ record ∈ authenticationBindings, record.device = component.id ∧ record.phase = "phase-0" ∧
        record.certificateAuthenticated = true ∧ record.preSharedCAKAuthenticated = false) ∧
    (∀ record ∈ authenticationBindings, ∃ component ∈ records.components,
      component.id = record.device ∧ (component.layer = some .inner ∨ component.layer = some .outer)) ∧
    (∀ record ∈ authenticationBindings, record.phase = "phase-1" →
      ∃ earlier ∈ authenticationBindings, earlier.phase = "phase-0" ∧ earlier.device = record.device ∧
        earlier.ikeUniqueId = record.ikeUniqueId ∧ earlier.childUniqueId = record.childUniqueId ∧
        earlier.caObservation = record.caObservation ∧ earlier.leafObservation = record.leafObservation) := by decide

lemma other_devices_do_not_report_certificate_authentication : ∀ component ∈ records.components,
    component.layer ≠ some .inner → component.layer ≠ some .outer →
    ((authenticationSettings.find? (fun setting => setting.component == component.id)).map
      CertificateAuthoritySetting.certificateAuthenticated).getD false = false := by decide

lemma logical_authorities_do_not_report_peer_authentication : ∀ setting ∈ authenticationSettings,
    ((authenticationSettings.find? (fun peer => peer.component == setting.authorityDevice.id)).map
      CertificateAuthoritySetting.certificateAuthenticated).getD false = false := by decide

lemma authentication_architecture_services (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ArchitectureServices (authenticationDeployment primitive) := by
  have settingsChecked : ∀ setting ∈ authenticationSettings, setting.Check := by
    intro setting stored
    obtain ⟨record, member, same⟩ := List.mem_map.mp stored
    subst setting
    exact (recorded_authentication_checks record member).1
  have services := checked_certificate_settings_supply_services authenticationSettings (deployment primitive) settingsChecked
  constructor
  · constructor
    · intro component listed relevant authenticated
      change component ∈ records.components ++ authenticationSettings.map CertificateAuthoritySetting.authorityDevice at listed
      rcases List.mem_append.mp listed with hardware | authority
      · by_cases encryptor : component.layer = some .inner ∨ component.layer = some .outer
        · obtain ⟨record, member, same, phase, certified, cak⟩ := recorded_authentication_coverage.1 component hardware encryptor
          have settingMember : record.setting ∈ authenticationSettings := List.mem_map.mpr ⟨record, member, rfl⟩
          have supported := (settingsChecked record.setting settingMember).1 certified
          refine ⟨record.setting.authorityDevice,
            List.mem_append_right _ (List.mem_map.mpr ⟨record.setting, settingMember, rfl⟩), ?_, ?_⟩
          · simp [CertificateAuthoritySetting.authorityDevice, supported.1, supported.2.1]
          · exact ⟨record.setting, settingMember, same, rfl⟩
        · have disabled := other_devices_do_not_report_certificate_authentication component hardware
            (fun inner => encryptor (Or.inl inner)) (fun outer => encryptor (Or.inr outer))
          change ((authenticationSettings.find? (fun setting => setting.component == component.id)).map
            CertificateAuthoritySetting.certificateAuthenticated).getD false = true at authenticated
          rw [disabled] at authenticated
          cases authenticated
      · obtain ⟨setting, member, same⟩ := List.mem_map.mp authority
        subst component
        have disabled := logical_authorities_do_not_report_peer_authentication setting member
        change ((authenticationSettings.find? (fun peer => peer.component == setting.authorityDevice.id)).map
          CertificateAuthoritySetting.certificateAuthenticated).getD false = true at authenticated
        rw [disabled] at authenticated
        cases authenticated
    · exact services.2
  · intro first firstMember second secondMember innerFirst innerSecond levels shared
    have firewall : ∃ firewall ∈ records.components, firewall.kind = .grayFirewall := by decide
    obtain ⟨firewall, member, kind⟩ := firewall
    exact ⟨firewall, List.mem_append_left _ member, kind⟩

lemma authentication_devices_unique (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∀ first ∈ (authenticationDeployment primitive).devices,
      ∀ second ∈ (authenticationDeployment primitive).devices, first.id = second.id → first = second := by
  change ∀ first ∈ records.components ++ authenticationSettings.map CertificateAuthoritySetting.authorityDevice,
    ∀ second ∈ records.components ++ authenticationSettings.map CertificateAuthoritySetting.authorityDevice,
      first.id = second.id → first = second
  decide

lemma authentication_static_bindings (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    DeviceDeploymentBindings (deviceBinding primitive) records.inventory.ifaces (authenticationDeployment primitive) := by
  have original := OuterTunnelNoBypass_Baseline.static_bindings primitive
  have processing : (deviceBinding primitive).ProcessingBound (authenticationDeployment primitive) := by
    obtain ⟨inventory, same, config, ifaceNames, componentNames, macNames, carrierBindings, remaining⟩ := original.processing.2.2
    refine ⟨original.processing.1, ?_, inventory, same, config, ifaceNames, componentNames, macNames, ?_, remaining⟩
    · simp only [Deployment.UDPBindingsCoherent,
        show (authenticationDeployment primitive).udpBindings = [] from rfl,
        List.not_mem_nil, false_implies, implies_true, and_self]
    · intro carrier member
      change carrier ∈ [] at member
      cases member
  exact ⟨processing, original.interfaceLinks, original.linkPolicies, original.headerGeneration,
    original.macsecKeys, original.ipsecKeys, original.redNetworks, original.peers,
    authentication_devices_unique primitive, original.interfaceIDs, original.tunnelIDs,
    original.interfaceIndices, original.ifaceRecords, original.physicalLinks, original.sourceEntries,
    original.macsecTunnels, original.ipsecTunnels⟩

theorem authentication_deployment_covered (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    (authenticationForwarding primitive).CoversDeployment (authenticationDeployment primitive) := by
  have budgets := size_checks_from_captured_records records installations OuterTunnelNoBypass_Baseline.roles
    OuterTunnelNoBypass_Baseline.linkPolicies (OuterTunnelNoBypass_Baseline.codec primitive)
    OuterTunnelNoBypass_BaselineNetwork.captured_size_checks
  apply standard_deployment_covered (deviceBinding primitive) records.inventory.ifaces (authenticationDeployment primitive) {}
    (authentication_static_bindings primitive) (by simp [ObservedHistory.Valid])
    (captured_iface_conditions records installations OuterTunnelNoBypass_Baseline.linkPolicies
      (OuterTunnelNoBypass_Baseline.codec primitive)
      OuterTunnelNoBypass_BaselineNetwork.captured_route_egresses OuterTunnelNoBypass_BaselineNetwork.captured_physical_endpoints
      OuterTunnelNoBypass_BaselineNetwork.captured_bridge_endpoints)
    (OuterTunnelNoBypass_Baseline.codec primitive) (requiredSizing OuterTunnelNoBypass_Baseline.roles)
    (sourceMtu OuterTunnelNoBypass_Baseline.roles) plaintextLimit authenticationLimit budgets.1
    ⟨fun _ => 64, fun _ => 64⟩ rfl (fun _ => ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩)
    (fun _ _ => rfl) rfl
    (source_mtu_minimum OuterTunnelNoBypass_Baseline.roles OuterTunnelNoBypass_BaselineNetwork.captured_mtu_checks) rfl
    (OuterTunnelNoBypass_Baseline.allowed_source_iface primitive)
    (OuterTunnelNoBypass_Baseline.network_sources primitive)

def flowKeyContexts (selected : IPsecFlowEndpoints) : String × String :=
  ((((records.tunnels.find? (fun tunnel => tunnel.id == selected.flow.innerTunnel)).map Tunnel.keyContext).getD ""),
    (((records.tunnels.find? (fun tunnel => tunnel.id == selected.flow.outerTunnel)).map Tunnel.keyContext).getD ""))

def IndependentLayerKeys (independentKeys : String → String → Prop) : Prop :=
  ∀ selected ∈ contexts, independentKeys (flowKeyContexts selected).1 (flowKeyContexts selected).2

def architectureInventory : Deployment :=
  { OuterTunnelNoBypass_Baseline.baseDeployment with
    devices := records.components ++ authenticationSettings.map CertificateAuthoritySetting.authorityDevice
    networks := networks
    tunnels := records.tunnels }

def FlowIPsecInventory (selected : IPsecFlowEndpoints) : Prop :=
  ∃ inner ∈ architectureInventory.tunnels, ∃ outer ∈ architectureInventory.tunnels,
    inner.id = selected.flow.innerTunnel ∧ outer.id = selected.flow.outerTunnel ∧
    inner.layer = .inner ∧ outer.layer = .outer ∧
    (inner.keyContext = (flowKeyContexts selected).1 ∧ outer.keyContext = (flowKeyContexts selected).2) ∧
    (∀ tunnel ∈ [inner, outer], ∃ sender ∈ architectureInventory.devices,
      ∃ receiver ∈ architectureInventory.devices,
      sender.id = tunnel.sender ∧ receiver.id = tunnel.receiver ∧
      sender.infrastructure = true ∧ receiver.infrastructure = true ∧
      sender.layer = some tunnel.layer ∧ receiver.layer = some tunnel.layer ∧ sender.site ≠ receiver.site ∧
      (tunnel.mechanism = .ipsec → sender.kind = .vpn ∧ receiver.kind = .vpn) ∧
      (tunnel.mechanism = .macsec → sender.kind = .macsec ∧ receiver.kind = .macsec)) ∧
    (∃ source ∈ architectureInventory.networks, ∃ destination ∈ architectureInventory.networks,
      source.id = selected.flow.sourceNetwork ∧ destination.id = selected.flow.destinationNetwork ∧
      inner.sender ∈ source.innerComponents ∧ inner.receiver ∈ destination.innerComponents ∧
      (∃ sender ∈ architectureInventory.devices, sender.id = outer.sender ∧ sender.site = source.site) ∧
      ∃ receiver ∈ architectureInventory.devices, receiver.id = outer.receiver ∧ receiver.site = destination.site) ∧
    outer.mechanism = .ipsec

set_option synthInstance.maxSize 2048 in
lemma recorded_flow_validity : ∀ selected ∈ contexts, FlowIPsecInventory selected := by
  unfold FlowIPsecInventory
  decide

lemma flows_valid (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) (independentKeys : String → String → Prop)
    (independent : IndependentLayerKeys independentKeys) :
    ∀ flow ∈ flows, flow.Valid (authenticationDeployment primitive) independentKeys := by
  intro flow member
  obtain ⟨selected, selectedMember, same⟩ := List.mem_map.mp member
  subst flow
  obtain ⟨inner, innerMember, outer, outerMember, innerName, outerName, innerLayer, outerLayer,
    keyContexts, endpoints, networks, sites⟩ := recorded_flow_validity selected selectedMember
  refine ⟨inner, innerMember, outer, outerMember, innerName, outerName, innerLayer, outerLayer, ?_, endpoints, networks, ?_⟩
  · rw [keyContexts.1, keyContexts.2]
    exact independent selected selectedMember
  · intro macsec
    rw [sites] at macsec
    cases macsec

end TDN.Deployments.NestedProtection_Baseline
