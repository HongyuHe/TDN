import TDN.Requirements.MscComplianceSchema

namespace TDN.Compliance

def Deployment.ForwardIngressSourceAllowed (d : Deployment) (device : String)
    (packet : PacketPolicy.Packet) : Prop :=
  match d.processing with
  | none => False
  | some inventory =>
    ∃ iface ∈ inventory.ifaces,
      ∃ interface ∈ d.interfaces,
        inventory.ifaceName iface = interface.id ∧ interface.device = device ∧
        inventory.componentName (inventory.configuration.ip.owner iface) = device ∧
        inventory.configuration.ip.interfaceName iface = packet.ingress ∧
        d.reachableSource interface.id packet.source

instance instDecidableForwardIngressSourceAllowed (d : Deployment) (device : String)
    (packet : PacketPolicy.Packet) [∀ interface, DecidablePred (d.reachableSource interface)] :
    Decidable (d.ForwardIngressSourceAllowed device packet) := by
  unfold Deployment.ForwardIngressSourceAllowed
  cases d.processing <;> infer_instance

def Deployment.GrayForwardPermission (d : Deployment) (interface : Interface)
    (hook : PacketProcessing.Hook) (traffic : Traffic) : Prop :=
  hook = .forward → d.ForwardIngressSourceAllowed interface.device traffic.packet

lemma forward_ingress_source_allowed_from_recorded_interface (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (iface : Nat) (member : iface ∈ inventory.ifaces)
    (interface : Interface) (interfaceMember : interface ∈ d.interfaces)
    (device : String) (name : inventory.ifaceName iface = interface.id)
    (owner : interface.device = device)
    (nativeOwner : inventory.componentName (inventory.configuration.ip.owner iface) = device)
    (packet : PacketPolicy.Packet)
    (ingress : inventory.configuration.ip.interfaceName iface = packet.ingress)
    (source : d.reachableSource interface.id packet.source) :
    d.ForwardIngressSourceAllowed device packet := by
  rw [Deployment.ForwardIngressSourceAllowed, present]
  exact ⟨iface, member, interface, interfaceMember, name, owner, nativeOwner, ingress, source⟩

lemma forward_permission_preserves_nonforward_cases (d : Deployment) (interface : Interface)
    (hook : PacketProcessing.Hook) (notForward : hook ≠ .forward) (traffic : Traffic) :
    d.GrayForwardPermission interface hook traffic := by
  intro forward
  exact False.elim (notForward forward)

lemma forward_permission_records_the_actual_incoming_source_check (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (traffic : Traffic)
    (permission : d.GrayForwardPermission interface .forward traffic) :
    ∃ iface ∈ inventory.ifaces, ∃ incoming ∈ d.interfaces,
      inventory.ifaceName iface = incoming.id ∧ incoming.device = interface.device ∧
      inventory.componentName (inventory.configuration.ip.owner iface) = interface.device ∧
      inventory.configuration.ip.interfaceName iface = traffic.packet.ingress ∧
      d.reachableSource incoming.id traffic.packet.source := by
  have source := permission rfl
  simpa only [Deployment.ForwardIngressSourceAllowed, present] using source


lemma forward_context_records_incoming_iface_and_filter_header
    (configuration : MultiProtocolForwarding.Config) (context : PacketProcessing.Context)
    (hook : context.hook = .forward) :
    (context.Packet configuration).ingress =
        configuration.ip.interfaceName context.state.enteredIface ∧
      (context.Packet configuration).source = context.header.source := by
  simp [PacketProcessing.Context.Packet, hook, MultiProtocolForwarding.policyHeader]

lemma forward_source_check_uses_visible_filter_header (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (context : PacketProcessing.Context) (hook : context.hook = .forward)
    (member : context.state.enteredIface ∈ inventory.ifaces)
    (interface : Interface) (interfaceMember : interface ∈ d.interfaces)
    (device : String) (name : inventory.ifaceName context.state.enteredIface = interface.id)
    (owner : interface.device = device)
    (nativeOwner : inventory.componentName
      (inventory.configuration.ip.owner context.state.enteredIface) = device)
    (source : d.reachableSource interface.id context.header.source) :
    d.ForwardIngressSourceAllowed device (context.Packet inventory.configuration) := by
  apply forward_ingress_source_allowed_from_recorded_interface d inventory present
    context.state.enteredIface member interface interfaceMember device name owner nativeOwner
  · exact (forward_context_records_incoming_iface_and_filter_header inventory.configuration context hook).1.symm
  · simpa only [(forward_context_records_incoming_iface_and_filter_header inventory.configuration context hook).2] using source

end TDN.Compliance
