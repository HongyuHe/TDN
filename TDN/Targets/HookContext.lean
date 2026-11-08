import TDN.Targets.ComplianceModel

namespace TDN.Compliance

lemma eligible_routed_packet_has_hook_context (d : Deployment) (interface : Interface)
    (direction : Direction) (context : PacketProcessing.Context) (traffic : Traffic)
    (supported : d.SupportedAt interface direction context traffic) :
    d.HookContext interface.id direction context.hook traffic.packet := by
  obtain ⟨inventory, present, member, applies, atHook, location, _, same, _⟩ := supported
  obtain ⟨entryMember, stateMember, enteredMember, owner, enteredOwner, selected⟩ := location
  have enteredDevice : interface.device =
      inventory.componentName (inventory.configuration.ip.owner context.state.enteredIface) := by
    rw [enteredOwner]
    exact owner.symm
  cases hook : context.hook with
  | input =>
    cases direction with
    | inbound =>
      simp only [hook] at selected
      refine ⟨inventory, present, context.state.enteredIface, enteredMember, selected.1,
        interface, member, rfl, enteredDevice, ?_⟩
      simp [PacketAtHook, HookDirection, hook, same, PacketProcessing.Context.Packet,
        MultiProtocolExecution.policyHeader]
    | outbound => simp [Interface.HookApplies, HookDirection, hook] at applies
  | forward =>
    cases direction with
    | inbound =>
      simp only [hook] at selected
      refine ⟨inventory, present, context.state.enteredIface, enteredMember, selected,
        interface, member, rfl, enteredDevice, ?_⟩
      simp [PacketAtHook, HookDirection, hook, same, PacketProcessing.Context.Packet,
        MultiProtocolExecution.policyHeader]
    | outbound =>
      simp only [hook] at selected
      refine ⟨inventory, present, context.state.iface, stateMember, selected,
        interface, member, rfl, owner.symm, ?_⟩
      simp [PacketAtHook, HookDirection, hook, same, PacketProcessing.Context.Packet,
        MultiProtocolExecution.policyHeader]
  | output =>
    cases direction with
    | inbound => simp [Interface.HookApplies, HookDirection, hook] at applies
    | outbound =>
      simp only [hook] at selected
      refine ⟨inventory, present, context.state.iface, stateMember, selected.1,
        interface, member, rfl, owner.symm, ?_⟩
      simp [PacketAtHook, HookDirection, hook, same, PacketProcessing.Context.Packet,
        MultiProtocolExecution.policyHeader]
  | link => simp [Interface.HookApplies, hook] at applies

lemma eligible_link_packet_has_hook_context (d : Deployment) (interface : Interface)
    (direction : Direction) (context : PacketProcessing.LinkContext) (traffic : Traffic)
    (supported : d.SupportedLinkAt interface direction context traffic) :
    d.HookContext interface.id direction .link traffic.packet := by
  obtain ⟨inventory, present, member, _, interfaceMember, _, _, name, owner,
    _, packet, _, _, _, bound⟩ := supported
  exact ⟨inventory, present, context.iface, member, name, interface, interfaceMember,
    rfl, owner.symm, packet ▸ bound⟩

theorem eligible_packet_has_hook_context (d : Deployment) (interface : Interface)
    (direction : Direction) (hook : PacketProcessing.Hook) (traffic : Traffic)
    (eligible : d.PacketEligibleAt interface direction hook traffic) :
    d.HookContext interface.id direction hook traffic.packet := by
  rcases eligible with ⟨context, same, supported, _⟩ | ⟨same, context, supported, _⟩
  · exact same ▸ eligible_routed_packet_has_hook_context d interface direction context traffic supported
  · exact same ▸ eligible_link_packet_has_hook_context d interface direction context traffic supported

end TDN.Compliance
