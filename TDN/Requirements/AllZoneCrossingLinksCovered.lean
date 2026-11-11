import TDN.Requirements.PerimeterInterfaceSlice
import TDN.Requirements.DeriveDataPlaneFromDeviceRecords

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

lemma recorded_link_path_is_native (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) (path : d.LinkPath inventory iface) : inventory.configuration.LinkPath iface := by
  rcases path with mac | bridge | carrier
  · exact Or.inl mac
  · obtain ⟨next, _, connected⟩ := bridge
    exact Or.inr (Or.inl ⟨next, connected⟩)
  · exact Or.inr (Or.inr carrier)

lemma physical_boundary_packet_has_actual_hook (configuration : Config) (iface : Nat)
    (direction : Direction) (encoded : LinkAdmission.Frame) :
    PacketAtHook (configuration.ip.interfaceName iface) direction .link
      (PhysicalBoundaryPacket configuration iface direction encoded) := by
  cases direction <;> simp [PacketAtHook, HookDirection, PhysicalBoundaryPacket,
    LinkAdmission.Frame.Packet]

lemma admitted_native_wire_has_outbound_physical_observation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (member : interface ∈ d.interfaces)
    (before after : MultiProtocolForwarding.State)
    (ifaceMember : before.iface ∈ inventory.ifaces)
    (path : d.LinkPath inventory before.iface)
    (name : inventory.ifaceName before.iface = interface.id)
    (nativeName : inventory.configuration.ip.interfaceName before.iface = interface.id)
    (owner : interface.device = inventory.componentName
      (inventory.configuration.ip.owner before.iface))
    (wire : MultiProtocolForwarding.Step inventory.configuration before .linkTransmit after)
    (admission : inventory.configuration.LinkStepAdmitted before .linkTransmit after)
    (supported : ∀ encoded,
      inventory.configuration.linkEncoding before.iface before.frame = some encoded →
      encoded.Describes before.frame →
      d.Supported (d.Observe (PhysicalBoundaryPacket inventory.configuration before.iface .outbound encoded))) :
    ∃ encoded,
      inventory.configuration.linkEncoding before.iface before.frame = some encoded ∧
      encoded.Describes before.frame ∧
      d.PhysicalBoundaryAccepts interface.id .outbound
        (d.Observe (PhysicalBoundaryPacket inventory.configuration before.iface .outbound encoded)) := by
  obtain ⟨encoded, encoding, describes, allowed⟩ :=
    (admission.1 rfl).1 (recorded_link_path_is_native d inventory before.iface path)
  refine ⟨encoded, encoding, describes, inventory, present, before.iface, ifaceMember,
    path, name, nativeName, interface, member, rfl, owner, encoded,
    .outbound before after encoded wire describes, rfl, supported encoded encoding describes, ?_⟩
  simpa [PhysicalBoundaryPacket, Deployment.Observe] using allowed

lemma admitted_native_wire_has_inbound_physical_observation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (member : interface ∈ d.interfaces)
    (before after : MultiProtocolForwarding.State)
    (ifaceMember : after.iface ∈ inventory.ifaces)
    (path : d.LinkPath inventory after.iface)
    (name : inventory.ifaceName after.iface = interface.id)
    (nativeName : inventory.configuration.ip.interfaceName after.iface = interface.id)
    (owner : interface.device = inventory.componentName
      (inventory.configuration.ip.owner after.iface))
    (wire : MultiProtocolForwarding.Step inventory.configuration before .linkTransmit after)
    (admission : inventory.configuration.LinkStepAdmitted before .linkTransmit after)
    (supported : ∀ encoded,
      inventory.configuration.linkEncoding after.iface after.frame = some encoded →
      encoded.Describes after.frame →
      d.Supported (d.Observe (PhysicalBoundaryPacket inventory.configuration after.iface .inbound encoded))) :
    ∃ encoded,
      inventory.configuration.linkEncoding after.iface after.frame = some encoded ∧
      encoded.Describes after.frame ∧
      d.PhysicalBoundaryAccepts interface.id .inbound
        (d.Observe (PhysicalBoundaryPacket inventory.configuration after.iface .inbound encoded)) := by
  obtain ⟨encoded, encoding, describes, allowed⟩ :=
    (admission.1 rfl).2.1 (recorded_link_path_is_native d inventory after.iface path)
  refine ⟨encoded, encoding, describes, inventory, present, after.iface, ifaceMember,
    path, name, nativeName, interface, member, rfl, owner, encoded,
    .inbound before after encoded wire describes, rfl, supported encoded encoding describes, ?_⟩
  simpa [PhysicalBoundaryPacket, Deployment.Observe] using allowed

lemma routed_iface_has_no_physical_boundary_admission (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (direction : Direction) (traffic : Traffic) :
    ¬ d.PhysicalBoundaryAccepts interface direction traffic := by
  rintro ⟨actual, same, iface, member, path, name, _⟩
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  obtain ⟨macs, bridges, carriers, _⟩ := routed iface member name
  rcases path with ⟨mac, configured, physical⟩ | ⟨next, nextMember, connected⟩ |
      ⟨carrier, configured, virtual⟩
  · exact macs mac configured physical
  · rcases connected with incoming | outgoing
    · exact (bridges next nextMember).1 incoming
    · exact (bridges next nextMember).2 outgoing
  · exact carriers carrier configured virtual

lemma admitted_physical_boundary_has_actual_directional_program (d : Deployment)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (admitted : d.PhysicalBoundaryAccepts interface direction traffic) :
    ∃ inventory, d.processing = some inventory ∧
      ∃ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface ∧
        ∃ record ∈ d.interfaces, record.id = interface ∧
          record.device = inventory.componentName (inventory.configuration.ip.owner iface) ∧
          ∃ encoded, PhysicalBoundaryView inventory.configuration direction iface encoded ∧
            traffic.packet = PhysicalBoundaryPacket inventory.configuration iface direction encoded ∧
            LinkAdmission.Admitted inventory.configuration.linkPolicies iface
              (direction = .outbound) traffic.packet := by
  obtain ⟨inventory, present, iface, member, _, name, _, record, recordMember,
    recordName, owner, encoded, view, packet, _, allowed⟩ := admitted
  exact ⟨inventory, present, iface, member, name, record, recordMember, recordName,
    owner, encoded, view, packet, allowed⟩

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

lemma physical_view_records_actual_native_wire (configuration : Config)
    (direction : Direction) (iface : Nat) (encoded : LinkAdmission.Frame)
    (view : PhysicalBoundaryView configuration direction iface encoded) :
    ∃ before after, MultiProtocolForwarding.Step configuration before .linkTransmit after ∧
      if direction = .outbound then iface = before.iface ∧ encoded.Describes before.frame
      else iface = after.iface ∧ encoded.Describes after.frame := by
  cases view with
  | outbound before after encoded wire describes => exact ⟨before, after, wire, rfl, describes⟩
  | inbound before after encoded wire describes => exact ⟨before, after, wire, rfl, describes⟩

lemma protection_disabled_native_transmit_has_physical_view (configuration : Config)
    (iface : MACIface) (configured : iface ∈ configuration.macIfaces)
    (before : MultiProtocolForwarding.State) (ready : before.datapathStage = .egressReady)
    (logical : before.iface = iface.logicalIface)
    (enabled : iface.settings.controlledPortEnabled = true)
    (disabled : iface.settings.protectFrames = false)
    (peer : Nat) (linked : configuration.physicalLink iface.physicalIface peer)
    (encoded : LinkAdmission.Frame) (describes : encoded.Describes before.frame) :
    ∃ physical received,
      MultiProtocolForwarding.Step configuration before .forwardWithoutEncap physical ∧
      MultiProtocolForwarding.Step configuration physical .linkTransmit received ∧
      physical.iface = iface.physicalIface ∧ physical.frame = before.frame ∧
      PhysicalBoundaryView configuration .outbound iface.physicalIface encoded := by
  let physical : MultiProtocolForwarding.State :=
    { before with initialEntry := false, iface := iface.physicalIface }
  let received : MultiProtocolForwarding.State :=
    { physical with initialEntry := false, iface := peer, datapathStage := .received, authenticated := [] }
  have transform : MultiProtocolForwarding.Step configuration before .forwardWithoutEncap physical :=
    .unprotectedMACsec iface configured ready logical enabled disabled
  have wire : MultiProtocolForwarding.Step configuration physical .linkTransmit received :=
    .linkTransmit peer ready linked
  exact ⟨physical, received, transform, wire, rfl, rfl,
    .outbound physical received encoded wire describes⟩

lemma protected_native_transmit_has_physical_view (configuration : Config)
    (iface : MACIface) (association : LayeredFrame.MACsecAssociation)
    (configured : iface ∈ configuration.macIfaces)
    (before : MultiProtocolForwarding.State) (ready : before.datapathStage = .egressReady)
    (logical : before.iface = iface.logicalIface)
    (emits : fullMACsecTransmit iface association before.frame.body)
    (peer : Nat) (linked : configuration.physicalLink iface.physicalIface peer)
    (encoded : LinkAdmission.Frame)
    (describes : encoded.Describes (configuration.macsecFrame before.frame association)) :
    ∃ physical received,
      MultiProtocolForwarding.Step configuration before .encryptMACsec physical ∧
      MultiProtocolForwarding.Step configuration physical .linkTransmit received ∧
      physical.iface = iface.physicalIface ∧
      physical.frame.body = .macsec association before.frame.body ∧
      PhysicalBoundaryView configuration .outbound iface.physicalIface encoded := by
  let physical : MultiProtocolForwarding.State :=
    { before with
      initialEntry := false
      iface := iface.physicalIface
      frame := configuration.macsecFrame before.frame association }
  let received : MultiProtocolForwarding.State :=
    { physical with initialEntry := false, iface := peer, datapathStage := .received, authenticated := [] }
  have transform : MultiProtocolForwarding.Step configuration before .encryptMACsec physical :=
    .encryptMACsec iface association configured ready logical emits
  have wire : MultiProtocolForwarding.Step configuration physical .linkTransmit received :=
    .linkTransmit peer ready linked
  exact ⟨physical, received, transform, wire, rfl,
    Config.macsecFrame_body configuration before.frame association,
    .outbound physical received encoded wire describes⟩

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open Compliance

lemma routed_iface_has_no_recorded_link_path (d : Deployment)
    (inventory : PacketProcessing.Inventory) (iface : Nat)
    (routed : DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface) : ¬ d.LinkPath inventory iface := by
  intro path
  rcases path with ⟨mac, member, physical⟩ | ⟨next, member, connected⟩ |
      ⟨carrier, member, virtual⟩
  · exact routed.1 mac member physical
  · rcases connected with incoming | outgoing
    · exact (routed.2.1 next member).1 incoming
    · exact (routed.2.1 next member).2 outgoing
  · exact routed.2.2.1 carrier member virtual

lemma routed_interface_has_boundary_policy_coverage (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (coverage : d.PolicyCoverage interface)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface) : d.BoundaryPolicyCoverage interface := by
  refine ⟨coverage, ?_⟩
  intro actual same iface member name path
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  exact False.elim (routed_iface_has_no_recorded_link_path d inventory iface
    (routed iface member name) path)

lemma previous_boundary_acceptance_is_retained (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic)
    (previous : d.DeviceBoundaryAccepts interface direction traffic ∨
      d.AcceptsAt interface direction .link traffic) : d.BoundaryAccepts interface direction traffic := by
  rcases previous with native | link
  · exact Or.inl native
  · exact Or.inr (Or.inl link)

lemma boundary_acceptance_without_physical_observation_is_unchanged (d : Deployment)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (absent : ¬ d.PhysicalBoundaryAccepts interface direction traffic) :
    d.BoundaryAccepts interface direction traffic ↔
      d.DeviceBoundaryAccepts interface direction traffic ∨ d.AcceptsAt interface direction .link traffic := by
  constructor
  · rintro (native | link | physical)
    · exact Or.inl native
    · exact Or.inr link
    · exact False.elim (absent physical)
  · exact previous_boundary_acceptance_is_retained d interface direction traffic

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open Compliance

lemma physical_MACsec_boundary_admission_is_link_admission (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String)
    (parents : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      ∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = iface)
    (direction : Direction) (traffic : Traffic)
    (admitted : d.PhysicalBoundaryAccepts interface direction traffic) :
    d.AcceptsAt interface direction .link traffic := by
  obtain ⟨actual, same, iface, member, path, name, nativeName, record, recordMember,
    recordName, owner, encoded, view, packet, supported, allowed⟩ := admitted
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  obtain ⟨mac, macMember, physical⟩ := parents iface member name
  have ethernet : PacketIsEthernet traffic.packet := by
    rw [packet]
    exact ⟨rfl, rfl⟩
  refine ⟨supported, ?_, ?_⟩
  · refine ⟨inventory, present, iface, member, name, record, recordMember, recordName, owner, ?_⟩
    rw [packet]
    exact physical_boundary_packet_has_actual_hook inventory.configuration iface direction encoded
  · refine ⟨⟨inventory, present, iface, member, name, Or.inl ⟨ethernet, ?_⟩⟩,
      inventory, present, iface, member, name, allowed⟩
    exact Or.inr (Or.inr ⟨mac, macMember, physical⟩)

lemma rejected_physical_program_excludes_boundary_admission (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (rejects : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      ¬ LinkAdmission.Admitted inventory.configuration.linkPolicies iface
        (direction = .outbound) traffic.packet) :
    ¬ d.PhysicalBoundaryAccepts interface direction traffic := by
  rintro ⟨actual, same, iface, member, _, name, _, _, _, _, _, _, _, _, _, allowed⟩
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  exact rejects iface member name allowed

end TDN.Requirements.Msc
