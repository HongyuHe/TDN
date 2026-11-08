import TDN.Targets.BoundaryPeerRules

namespace TDN.Targets.Complete
open Compliance MultiProtocolExecution

lemma processing_named_iface_has_interface_owner (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (coherent : d.ProcessingCoherent) (interface : Interface) (member : interface ∈ d.interfaces)
    (iface : Nat) (ifaceMember : iface ∈ inventory.ifaces) (name : inventory.ifaceName iface = interface.id) :
    inventory.componentName (inventory.configuration.ip.owner iface) = interface.device := by
  obtain ⟨actual, same, mka, tunnels, ifaces, interfaces, injective, network, mtus,
    sizes, valid, routes, addresses, forward, policies⟩ := coherent
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  obtain ⟨other, otherMember, otherName, owner⟩ := interfaces interface member
  have equal := injective iface ifaceMember other otherMember (name.trans otherName.symm)
  exact equal.symm ▸ owner

lemma processing_routes_preserve_owners (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (coherent : d.ProcessingCoherent) : RouteOwnersCoherent inventory.configuration := by
  obtain ⟨actual, same, mka, tunnels, ifaces, interfaces, injective, network, mtus,
    sizes, valid, routes, addresses, forward, policies⟩ := coherent
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  intro route member
  exact (routes route member).2.2

theorem admitted_native_boundary_has_intended_peer (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (coherent : d.ProcessingCoherent) (addressCoherent : d.AddressInventoryCoherent)
    (interface : Interface) (member : interface ∈ d.interfaces)
    (peers : List BoundaryPeer) (bound : ∀ record ∈ peers, record.Bound d)
    (policies : ∀ iface ∈ inventory.ifaces, ∀ policy ∈ inventory.configuration.ip.outbound iface,
      ∃ record ∈ peers, record.source = inventory.componentName (inventory.configuration.ip.owner iface) ∧
        policy.receiver = record.destinationAddress)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ (policy.direction = .outbound →
          ∀ rule ∈ policy.rules, rule.verdict = .allow →
            OutboundPeerRule interface.device (inventory.configuration.ip.interfaceName iface) peers rule))
    (traffic : Traffic) (accepted : d.NativeBoundaryAccepts interface.id .outbound traffic) :
    d.IntendedPacketPeer interface.device traffic := by
  obtain ⟨actual, same, filtering, filteringMember, context, supported, admitted,
    coherentFrame, iface, ifaceMember, ifaceName, view, trafficSupported⟩ := accepted
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  obtain ⟨atHook, location, hookDirection⟩ :=
    supported_native_context_has_packet_hook d inventory present filtering .outbound context supported
  have preserved := boundary_view_preserves_owner inventory.configuration
    (processing_routes_preserve_owners d inventory present coherent) context atHook .outbound
    iface traffic.packet view
  have owner : inventory.componentName (inventory.configuration.ip.owner context.state.iface) =
      interface.device :=
    (congrArg inventory.componentName preserved.symm).trans
      (processing_named_iface_has_interface_owner d inventory present coherent interface member
        iface ifaceMember ifaceName)
  have selected : ∀ policy ∈ inventory.configuration.ip.outbound context.state.iface,
      ∃ record ∈ peers, record.source = interface.device ∧ policy.receiver = record.destinationAddress := by
    intro policy policyMember
    obtain ⟨record, recordMember, source, destination⟩ :=
      policies context.state.iface location.2.1 policy policyMember
    exact ⟨record, recordMember, source.trans owner, destination⟩
  have visible : inventory.configuration.visibleHeader context.state.frame = some context.header := by
    simpa [Config.visibleHeader, mode] using atHook.1
  apply outbound_boundary_peer_from_raw_destination_or_required_transform d addressCoherent
    inventory.configuration context interface.device peers bound selected iface traffic.packet traffic
    trafficSupported rfl visible view
  intro sameIface
  have localName := native_outbound_context_has_interface_name d inventory filtering context location
  have name : filtering.id = interface.id :=
    localName.symm.trans ((congrArg inventory.ifaceName sameIface.symm).trans ifaceName)
  have raw := admitted_native_packet_has_peer_or_outbound_annotation d inventory present interface peers
    routed checks (d.Observe (context.Packet inventory.configuration))
      ⟨context.hook, name ▸ admitted⟩
  rcases raw with ⟨record, recordMember, source, destination, protocol⟩ | required
  · refine Or.inl ⟨record, recordMember, source, ?_, ?_⟩
    · cases hook : context.hook <;>
        simpa [Deployment.Observe, PacketProcessing.Context.Packet, hook, policyHeader] using destination
    · cases hook : context.hook <;>
        simpa [Deployment.Observe, PacketProcessing.Context.Packet, hook, policyHeader] using protocol
  · exact Or.inr required

end TDN.Targets.Complete
