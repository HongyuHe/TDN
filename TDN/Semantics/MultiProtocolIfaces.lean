import TDN.Semantics.MultiProtocolExecution

namespace TDN.MultiProtocolExecution

structure IfaceConditions (configuration : Config) (ifaces : List Nat) : Prop where
  routeTargets : ∀ route ∈ configuration.ip.routes, route.egress ∈ ifaces
  physicalEndpoints : ∀ first second, configuration.physicalLink first second →
    first ∈ ifaces ∧ second ∈ ifaces
  bridgeEndpoints : ∀ first second, configuration.bridge first second →
    first ∈ ifaces ∧ second ∈ ifaces
  macEndpoints : ∀ mac ∈ configuration.macIfaces,
    mac.logicalIface ∈ ifaces ∧ mac.physicalIface ∈ ifaces
  carrierEndpoints : ∀ carrier ∈ configuration.carriers,
    carrier.virtualIface ∈ ifaces ∧ carrier.routingIface ∈ ifaces

lemma step_preserves_iface_inventory {configuration : Config} {ifaces : List Nat}
    (conditions : IfaceConditions configuration ifaces)
    {before after : State} {action : Action}
    (step : Step configuration before action after) (present : before.iface ∈ ifaces) :
    after.iface ∈ ifaces := by
  cases step with
  | receive => exact present
  | route route _ _ chosen _ => exact conditions.routeTargets route chosen.1
  | routeLocalOutput route _ _ chosen _ => exact conditions.routeTargets route chosen.1
  | forwardFilter => exact present
  | outputFilter => exact present
  | encryptIPsec => exact present
  | routeOuterPacket route _ _ chosen _ => exact conditions.routeTargets route chosen.1
  | passWithoutTransform => exact present
  | decryptIPsec => exact present
  | inputFilter => exact present
  | deliver => exact present
  | deliverEthernet => exact present
  | linkTransmit next _ linked => exact (conditions.physicalEndpoints _ next linked).2
  | bridge next _ linked => exact (conditions.bridgeEndpoints _ next linked).2
  | bridgeOutput next _ linked => exact (conditions.bridgeEndpoints _ next linked).2
  | encryptMACsec iface _ configured _ _ _ => exact (conditions.macEndpoints iface configured).2
  | unprotectedMACsec iface configured _ _ _ _ => exact (conditions.macEndpoints iface configured).2
  | decryptMACsec iface _ _ _ configured _ _ _ _ _ =>
    exact (conditions.macEndpoints iface configured).1
  | uncheckedMACsec iface configured _ _ _ => exact (conditions.macEndpoints iface configured).1
  | encapsulate iface configured _ _ => exact (conditions.carrierEndpoints iface configured).2
  | decapsulate iface _ configured _ _ _ => exact (conditions.carrierEndpoints iface configured).1
  | drop => exact present

theorem all_executions_stay_in_iface_inventory {configuration : Config} {ifaces : List Nat}
    (conditions : IfaceConditions configuration ifaces)
    {before after : State} {actions : List Action}
    (run : (lts configuration).MTr before actions after) (present : before.iface ∈ ifaces) :
    after.iface ∈ ifaces := by
  have preserved : (lts configuration).TrInv (fun state => state.iface ∈ ifaces) :=
    fun _ _ _ step member => step_preserves_iface_inventory conditions step member
  exact Cslib.LTS.mtrInv_of_trInv preserved _ _ _ run present

end TDN.MultiProtocolExecution
