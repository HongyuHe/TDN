import TDN.Deployments.MtuSizing_BaselineData

import TDN.Deployments.RedEndpointNetworkIds

namespace TDN.Deployments.OuterTunnelNoBypass_BaselineNetwork
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

abbrev originalRecords := MtuSizing_Baseline.records
abbrev installations := MtuSizing_Baseline.installations
abbrev networks := MtuSizing_Baseline.networks
abbrev entries := MtuSizing_Baseline.entries
abbrev roles := MtuSizing_Baseline.roles
abbrev attachments := MtuSizing_Baseline.attachments
abbrev epoch := MtuSizing_Baseline.epoch
abbrev linkPolicies := MtuSizing_Baseline.linkPolicies
abbrev services := MtuSizing_Baseline.services
abbrev flows := MtuSizing_Baseline.flows

def records : Records := RedEndpointNetworkIds.networkIdView originalRecords entries

lemma red_endpoint_network_ids_checked :
    (∀ entry ∈ entries,
      originalRecords.componentName (DataPlaneForwarding.ifaceAt originalRecords.nativeIfaces entry.hostIface).owner = entry.sourceHost ∧
      records.configuration.ip.ifaceSecurityDomain entry.hostIface = some entry.originDomain ∧
      ((entries.find? (fun selected => selected.originDomain == entry.originDomain)).map SourceEntry.network) = some entry.network) ∧
    (∀ owner ∈ List.range originalRecords.nativeDevices.length,
      (DataPlaneForwarding.deviceAt originalRecords.nativeDevices owner).ifaceSecurityDomain.isSome = true ↔
      ∃ entry ∈ entries, entry.sourceHost = originalRecords.componentName owner ∧
        (DataPlaneForwarding.ifaceAt originalRecords.nativeIfaces entry.hostIface).owner = owner) ∧
    ∀ entry ∈ entries, ∀ iface ∈ records.inventory.ifaces,
      (DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner =
        (DataPlaneForwarding.ifaceAt records.nativeIfaces entry.hostIface).owner →
      records.configuration.ip.ifaceSecurityDomain iface = some entry.originDomain := by native_decide

end TDN.Deployments.OuterTunnelNoBypass_BaselineNetwork
