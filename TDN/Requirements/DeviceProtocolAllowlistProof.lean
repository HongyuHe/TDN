import TDN.Requirements.DerivePerimeterContext

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

theorem admitted_native_boundary_has_IPsec_protocol (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) (interface : String)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      ∀ policy ∈ d.policies, policy.interface = interface →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          DeviceProtocolRule (inventory.configuration.ip.interfaceName iface) policy.direction rule)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.DeviceBoundaryAccepts interface direction traffic) :
    IPsecPacket traffic.packet := by
  obtain ⟨actual, same, filtering, filteringMember, context, supported, admitted,
    coherent, iface, ifaceMember, ifaceName, view, trafficSupported⟩ := accepted
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  obtain ⟨atHook, location, hookDirection⟩ :=
    supported_native_context_has_packet_hook d inventory present filtering direction context supported
  have raw : filtering.id = interface →
      IPsecPacket (context.Packet inventory.configuration) ∨
        if direction = .inbound then (context.Packet inventory.configuration).matchedInboundPolicyIds ≠ []
        else (context.Packet inventory.configuration).matchedOutboundPolicyIds ≠ [] := by
    intro name
    have acceptedRaw : d.Accepts interface direction
        (d.Observe (context.Packet inventory.configuration)) := by
      exact ⟨context.hook, name ▸ admitted⟩
    exact admitted_native_packet_has_protocol_or_annotation d inventory present interface routed checks
      direction _ acceptedRaw
  have visible : inventory.configuration.visibleHeader context.state.frame = some context.header := by
    have rawVisible : context.state.frame.visibleHeader = some context.header := atHook.1
    simpa [Config.visibleHeader, mode] using rawVisible
  generalize packetIdentity : traffic.packet = packet at view ⊢
  cases direction with
  | inbound =>
    have incomingName := device_inbound_context_has_interface_name d inventory filtering context atHook location
    have entryIface : iface = context.entry.iface := by cases view; rfl
    have name : filtering.id = interface := incomingName.symm.trans
      ((congrArg inventory.ifaceName entryIface.symm).trans ifaceName)
    exact inbound_boundary_IPsec_from_raw_protocol_or_authentication inventory.configuration processing mode
      bounds context iface packet atHook hookDirection coherent view (by simpa using raw name)
  | outbound =>
    cases view with
    | outbound filtered ready afterWire filter run wire header boundaryVisible =>
      have preserved := boundary_filter_preserves_frame_and_iface inventory.configuration context filtered filter
      have suffix := first_ready_run_from_filtered_is_native_suffix inventory.configuration preserved.2.2 run
      cases suffix with
      | IPsec protect route =>
        exact (IPsec_packet_at_boundary_header _ _ _ _).mpr
          (configured_IPsec_suffix_has_IPsec_boundary_header inventory.configuration protect route header boundaryVisible)
      | forwardWithoutEncap step datapathStage =>
        have sameIface : ready.iface = context.state.iface := by
          have same : ready.iface = filtered.iface := by cases step <;> simp_all
          exact same.trans preserved.2.1
        have outgoingName := device_outbound_context_has_interface_name d inventory filtering context location
        have name : filtering.id = interface := outgoingName.symm.trans
          ((congrArg inventory.ifaceName sameIface.symm).trans ifaceName)
        have permitted : IPsecPacket (context.Packet inventory.configuration) ∨
            ∃ requestId, requestId ∈ (context.Packet inventory.configuration).matchedOutboundPolicyIds := by
          rcases raw name with protocol | required
          · exact Or.inl protocol
          · change (context.Packet inventory.configuration).matchedOutboundPolicyIds ≠ [] at required
            exact Or.inr (List.exists_mem_of_ne_nil _ required)
        exact outbound_boundary_IPsec_from_raw_protocol_or_required_transform inventory.configuration context
          ready.iface _ visible (.outbound filtered ready afterWire filter run wire header boundaryVisible) permitted

end TDN.Requirements.Msc
