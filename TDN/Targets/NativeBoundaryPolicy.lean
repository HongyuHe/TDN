import TDN.Targets.BoundaryNativeChecks
import TDN.Targets.PhysicalBoundaryCoverage

namespace TDN.Targets.Complete
open Compliance MultiProtocolExecution

lemma routed_boundary_admission_is_native (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (device : Device) (interface : Interface) (crypto : CryptographicBoundary device interface)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface)
    (direction : Direction) (traffic : Traffic)
    (admitted : d.BoundaryAdmission device interface direction traffic) :
    d.NativeBoundaryAccepts interface.id direction traffic := by
  simp only [Deployment.BoundaryAdmission, crypto, ↓reduceIte] at admitted
  rcases admitted with native | link | physical
  · exact native
  · exact False.elim (PolicyDerivation.routed_iface_has_no_link_operation d inventory present
      interface.id routed direction traffic link.2.2)
  · exact False.elim (routed_iface_has_no_physical_boundary_admission d inventory present
      interface.id routed direction traffic physical)

theorem native_boundary_interface_filtering_from_checks (d : Deployment)
    (focus : d.focus = none)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) (required : Bool)
    (internal : String → Bool) (localOuter : String → String)
    (endpoints : List RedServiceEndpoint) (peers : List BoundaryPeer)
    (controls : List BoundaryControlFlow)
    (approval : d.policyApproved = BoundaryControlApproval controls)
    (observations : BoundaryControlObservationChecks d controls)
    (address : d.AddressInventoryCoherent) (coherent : d.ProcessingCoherent)
    (udp : d.UDPBindingsCoherent) (indices : policyIndicesChecked d = true)
    (endpointBound : ∀ endpoint ∈ endpoints, endpoint.Bound d)
    (peerBound : ∀ record ∈ peers, record.Bound d)
    (peerPolicies : ∀ iface ∈ inventory.ifaces, ∀ policy ∈ inventory.configuration.ip.outbound iface,
      ∃ record ∈ peers, record.source = inventory.componentName (inventory.configuration.ip.owner iface) ∧
        policy.receiver = record.destinationAddress)
    (roles : ∀ device ∈ d.devices,
      (device.layer = some .outer → device.kind = .vpn) ∧
      (device.kind = .outerFirewall → device.layer = none))
    (routed : ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices, interface.device = device.id →
      ((device.layer = some .outer ∧ interface.zone = .black) ∨
        (device.layer = some .inner ∧ interface.zone = .gray) ∨
        (device.layer = some .inner ∧ interface.zone = .red) ∨
        (device.kind = .outerFirewall ∧ required = true)) →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        PolicyDerivation.RoutedIface inventory iface)
    (checks : ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices, interface.device = device.id →
      BoundaryInterfaceChecks d inventory required internal localOuter endpoints peers controls interface device) :
    msc_boundary_interface_filtering d required internal localOuter := by
  have cleared : { d with focus := none } = d := by
    cases d
    simp_all
  unfold msc_boundary_interface_filtering
  rw [cleared]
  refine ⟨address, coherent, udp, ?_⟩
  intro interface member _ device deviceMember _ owner assessed
  obtain ⟨protocolChecks, peerChecks, redChecks, firewallChecks⟩ :=
    checks interface member device deviceMember owner
  have ifaceRouted : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface :=
    routed interface member device deviceMember owner assessed
  refine ⟨routed_interface_has_boundary_policy_coverage d inventory present interface
    (policy_coverage_from_checked_indices d indices interface member) ifaceRouted, ?_⟩
  intro direction traffic admitted
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro outer black
    have crypto : CryptographicBoundary device interface := Or.inl ⟨outer, black⟩
    have native := routed_boundary_admission_is_native d inventory present device interface crypto
      ifaceRouted direction traffic admitted
    have protocol := admitted_native_boundary_has_IPsec_protocol d inventory present processing mode bounds
      interface.id ifaceRouted (protocolChecks crypto) direction traffic native
    have vpn := (roles device deviceMember).1 outer
    refine ⟨fun _ => Or.inl (Or.inl protocol), ?_, ?_⟩
    · intro macsec
      rw [vpn] at macsec
      cases macsec
    · intro outbound
      subst direction
      have peer := admitted_native_boundary_has_intended_peer d inventory present processing mode
        coherent address interface member peers peerBound peerPolicies ifaceRouted (peerChecks ⟨outer, black⟩)
        traffic native
      exact Or.inl (owner ▸ peer)
  · intro inner gray
    have crypto : CryptographicBoundary device interface := Or.inr ⟨inner, gray⟩
    have native := routed_boundary_admission_is_native d inventory present device interface crypto
      ifaceRouted direction traffic admitted
    have protocol := admitted_native_boundary_has_IPsec_protocol d inventory present processing mode bounds
      interface.id ifaceRouted (protocolChecks crypto) direction traffic native
    exact Or.inl (Or.inl (Or.inl (Or.inl protocol)))
  · intro inner red
    have nonCrypto : ¬ CryptographicBoundary device interface := by
      simp [CryptographicBoundary, inner, red]
    have raw : d.Accepts interface.id direction traffic := by
      simpa only [Deployment.BoundaryAdmission, nonCrypto, ↓reduceIte] using admitted
    have service := Red_admission_from_local_rule_checks d inventory present interface endpoints
      endpointBound ifaceRouted (redChecks ⟨inner, red⟩) direction traffic raw
    simpa only [owner] using service
  · intro firewall requiredTrue
    have noLayer := (roles device deviceMember).2 firewall
    have nonCrypto : ¬ CryptographicBoundary device interface := by
      simp [CryptographicBoundary, noLayer]
    have raw : d.Accepts interface.id direction traffic := by
      simpa only [Deployment.BoundaryAdmission, nonCrypto, ↓reduceIte] using admitted
    obtain ⟨outerRole, checked⟩ := firewallChecks ⟨firewall, requiredTrue⟩
    have firewallRole : d.IsDevice interface.device .outerFirewall :=
      ⟨device, deviceMember, owner.symm, firewall⟩
    have result := firewall_control_admission_from_local_rule_checks d inventory present controls approval observations interface
      (localOuter device.id) (internal interface.id) firewallRole outerRole ifaceRouted checked direction traffic raw
    rcases result with tunnel | control
    · refine ⟨Or.inl (Or.inl (Or.inl (Or.inl tunnel.1))), ?_⟩
      intro inbound _
      simpa only [owner] using tunnel.2 inbound
    · refine ⟨Or.inr (owner ▸ control), ?_⟩
      intro inbound unapproved
      exact False.elim (unapproved (owner ▸ control))

end TDN.Targets.Complete
