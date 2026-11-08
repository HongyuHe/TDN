import TDN.Evidence.SizingBaselineInventory
import TDN.Evidence.SizingBaselineStaticChecks
import TDN.Evidence.SizingBaselineBudgetChecks

namespace TDN.Imported.SizingBaseline
open Compliance Targets Targets.Complete OuterGrayNativeModel PacketSizingRecords CanonicalExecution

def codec (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : Execution.Seal → IPsecFrameEncoding.Parameters) :=
  capturedCodec installations material primitive parameters

def deployment (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : Execution.Seal → IPsecFrameEncoding.Parameters) (base : Deployment) :=
  completeDeployment records installations linkPolicies (codec material primitive parameters)
    networks attachments services base

def native (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : Execution.Seal → IPsecFrameEncoding.Parameters) :=
  prototype records installations entries roles linkPolicies epoch (codec material primitive parameters) material

def execution (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : Execution.Seal → IPsecFrameEncoding.Parameters) (base : Deployment) :=
  model (native material primitive parameters) records.inventory.ifaces
    (deployment material primitive parameters base) {}

theorem complete_recorded_packet_size_configuration
    (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : Execution.Seal → IPsecFrameEncoding.Parameters) (base : Deployment)
    (privateMaterial : PrivateMaterialAssurance installations material) :
    Targets.Complete.msc_packet_size_configuration (deployment material primitive parameters base)
      (execution material primitive parameters base)
      (sizedWireModel (codec material primitive parameters) (sourceMtu roles) (sourceMtu roles))
      (settings roles) [] := by
  apply complete_recorded_packet_sizing records installations entries roles linkPolicies epoch
    (codec material primitive parameters) material networks attachments services base flows
    (captured_structure base) captured_interface_selection captured_program_atoms captured_source_bindings
    captured_network_sources captured_bridge_policies
    (captured_iface_conditions records installations linkPolicies (codec material primitive parameters)
      captured_route_targets captured_physical_endpoints captured_bridge_endpoints)
    captured_SA_inventory_checks captured_tunnels privateMaterial captured_networks_nonempty
    captured_devices_unique captured_interfaces_unique captured_tunnels_unique
    captured_size_checks captured_mtu_checks (captured_sizing_inventory _ base)

end TDN.Imported.SizingBaseline
