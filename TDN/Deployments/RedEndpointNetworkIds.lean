import TDN.Deployments.MtuSizing_Records

namespace TDN.Deployments.RedEndpointNetworkIds
open OuterToGray_DeviceModel MtuSizing_Records

def endpointNetworkId (records : Records) (entries : List SourceEntry) (owner : Nat) : Option Nat :=
  (entries.find? (fun entry => entry.sourceHost == records.componentName owner &&
    (DataPlaneForwarding.ifaceAt records.nativeIfaces entry.hostIface).owner == owner)).map SourceEntry.originDomain

def networkIdView (records : Records) (entries : List SourceEntry) : Records :=
  { records with nativeDevices := records.nativeDevices.mapIdx (fun owner device =>
      { device with ifaceSecurityDomain := if device.ifaceSecurityDomain.isSome then endpointNetworkId records entries owner else none }) }

lemma network_id_view_preserves_other_records (records : Records) (entries : List SourceEntry) :
    { networkIdView records entries with nativeDevices := records.nativeDevices } = records := by
  cases records
  rfl

end TDN.Deployments.RedEndpointNetworkIds
