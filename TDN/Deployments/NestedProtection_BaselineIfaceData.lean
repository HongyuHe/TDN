import TDN.Deployments.NestedProtection_BaselineFlowData

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records LayeredFrame MultiProtocolForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma recorded_iface_zones : ∀ iface ∈ records.inventory.ifaces, ∀ interface ∈ records.interfaces,
    records.ifaceName iface = interface.id →
    (interface.zone = .gray → expectedEncapStack iface = [1]) ∧
    (interface.zone = .black → expectedEncapStack iface = [2, 1]) := by native_decide

lemma recorded_sources_are_red : ∀ entry ∈ entries, ∀ interface ∈ records.interfaces,
    records.ifaceName entry.iface = interface.id → interface.zone ≠ .black := by native_decide

lemma recorded_recipient_addresses : ∀ selected ∈ contexts, ∀ iface ∈ records.inventory.ifaces,
    capturedConfiguration.ip.ifaceSecurityDomain iface ≠ none →
    ∀ interface ∈ records.interfaces, interface.device = records.componentName (capturedConfiguration.ip.owner iface) →
    ∀ address ∈ interface.address.toList ++ interface.namespaceAddresses,
    selected.remoteLow ≤ address → address ≤ selected.remoteHigh →
      (capturedConfiguration.ip.ifaceSecurityDomain iface).map OuterTunnelNoBypass_Baseline.redNetwork =
        some selected.flow.destinationNetwork := by native_decide

end TDN.Deployments.NestedProtection_Baseline
