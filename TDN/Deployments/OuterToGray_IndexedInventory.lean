import TDN.Deployments.OuterToGray_DeviceModel
import TDN.Requirements.DeviceAndInterfaceNameTable

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance Requirements

def Records.IndexedOwnerChecks (records : Records) : Prop :=
  ∀ interface ∈ records.interfaces,
    records.componentName (records.configuration.ip.owner (records.ifaceIndex interface)) = interface.device

instance (records : Records) : Decidable records.IndexedOwnerChecks := by
  unfold Records.IndexedOwnerChecks
  infer_instance

theorem Records.indexed_interface_iface_bindings (records : Records)
    (names : records.ifaceNames = records.interfaces.map Interface.id)
    (length : records.ifaceNames.length = records.nativeIfaces.length)
    (unique : records.ifaceNames.Nodup)
    (selection : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧
        records.ifaceName (records.ifaceIndex interface) = interface.id)
    (owners : records.IndexedOwnerChecks) :
    (∀ iface ∈ records.inventory.ifaces, ∃ interface ∈ records.interfaces,
      interface.id = records.ifaceName iface ∧
        interface.device = records.componentName (records.configuration.ip.owner iface)) ∧
    (∀ interface ∈ records.interfaces, ∃ iface ∈ records.inventory.ifaces,
      records.ifaceName iface = interface.id ∧
        records.componentName (records.configuration.ip.owner iface) = interface.device) := by
  constructor
  · intro iface ifaceMember
    have count : records.interfaces.length = records.nativeIfaces.length := by
      simpa only [names, List.length_map] using length
    have bound : iface < records.interfaces.length := by
      rw [count]
      exact List.mem_range.mp ifaceMember
    let interface := records.interfaces[iface]
    have member : interface ∈ records.interfaces := List.getElem_mem bound
    have name : interface.id = records.ifaceName iface := by
      simp [interface, Records.ifaceName, names, List.getElem?_eq_getElem bound]
    have selected := selection interface member
    have same : records.ifaceIndex interface = iface :=
      indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length length unique
        _ selected.1 _ ifaceMember (selected.2.trans name)
    refine ⟨interface, member, name, ?_⟩
    have owner := owners interface member
    rw [same] at owner
    exact owner.symm
  · intro interface member
    exact ⟨records.ifaceIndex interface, (selection interface member).1,
      (selection interface member).2, owners interface member⟩

end TDN.Deployments.OuterToGray_DeviceModel
