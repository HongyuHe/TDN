import TDN.Deployments.MtuSizing_SharedData

import TDN.Deployments.RedEndpointNetworkIds

namespace TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

abbrev originalRecords := MtuSizing_Shared.records
abbrev installations := MtuSizing_Shared.installations
abbrev networks := MtuSizing_Shared.networks
abbrev entries := MtuSizing_Shared.entries
abbrev roles := MtuSizing_Shared.roles
abbrev attachments := MtuSizing_Shared.attachments
abbrev epoch := MtuSizing_Shared.epoch
abbrev linkPolicies := MtuSizing_Shared.linkPolicies
abbrev services := MtuSizing_Shared.services
abbrev flows := MtuSizing_Shared.flows

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
      records.configuration.ip.ifaceSecurityDomain iface = some entry.originDomain := by decide

end TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
