import TDN.Targets.ComplianceModel

namespace TDN.Compliance
open MultiProtocolExecution

lemma wire_arrival_has_recorded_ingress (d : Deployment)
    (inventory : PacketProcessing.Inventory) {before after : MultiProtocolExecution.State}
    (ifaceRecorded : before.iface ∈ inventory.ifaces)
    (arrival : MultiProtocolExecution.Step inventory.configuration before .linkTransmit after) :
    d.NativeArrivalEligible inventory after := by
  cases arrival with
  | linkTransmit next datapathStage linked =>
    exact Or.inl (Or.inl ⟨before.iface, ifaceRecorded, linked⟩)

lemma MACsec_arrival_has_configured_ingress (d : Deployment)
    (inventory : PacketProcessing.Inventory) {before after : MultiProtocolExecution.State}
    (arrival : MultiProtocolExecution.Step inventory.configuration before .decryptMACsec after) :
    d.NativeArrivalEligible inventory after := by
  cases arrival with
  | decryptMACsec iface association transmitted body configured datapathStage physical encrypted installed identity =>
    exact Or.inl (Or.inr (Or.inl ⟨iface, configured, rfl⟩))

lemma carrier_arrival_has_configured_ingress (d : Deployment)
    (inventory : PacketProcessing.Inventory) {before after : MultiProtocolExecution.State}
    (arrival : MultiProtocolExecution.Step inventory.configuration before .decapsulate after) :
    d.NativeArrivalEligible inventory after := by
  cases arrival with
  | decapsulate iface body configured datapathStage owner unwrapped =>
    exact Or.inl (Or.inr (Or.inr ⟨iface, configured, rfl⟩))

lemma source_bound_local_reinjection_is_eligible (d : Deployment)
    (inventory : PacketProcessing.Inventory) (state : MultiProtocolExecution.State)
    (header : PacketPolicy.Packet) (visible : state.frame.visibleHeader = some header)
    (source : d.LocalSourceAddress
      (inventory.componentName (inventory.configuration.ip.owner state.iface)) header) :
    d.NativeArrivalEligible inventory state := by
  exact Or.inr ⟨header, visible, source⟩

lemma local_input_context_has_no_forward_arrival_obligation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (context : PacketProcessing.Context)
    (hook : context.hook = .input) :
    context.hook = .forward → d.NativeArrivalEligible inventory context.entry := by
  intro forward
  cases hook.symm.trans forward

lemma local_output_context_has_no_forward_arrival_obligation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (context : PacketProcessing.Context)
    (hook : context.hook = .output) :
    context.hook = .forward → d.NativeArrivalEligible inventory context.entry := by
  intro forward
  cases hook.symm.trans forward

end TDN.Compliance
