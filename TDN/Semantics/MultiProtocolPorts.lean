import TDN.Semantics.MultiProtocolExecution

namespace TDN.MultiProtocolExecution

structure PortConditions (configuration : Config) (ports : List Nat) : Prop where
  routeTargets : ∀ route ∈ configuration.ip.routes, route.egress ∈ ports
  physicalEndpoints : ∀ first second, configuration.physicalLink first second →
    first ∈ ports ∧ second ∈ ports
  bridgeEndpoints : ∀ first second, configuration.bridge first second →
    first ∈ ports ∧ second ∈ ports
  macEndpoints : ∀ mac ∈ configuration.macPorts,
    mac.logicalPort ∈ ports ∧ mac.physicalPort ∈ ports
  carrierEndpoints : ∀ carrier ∈ configuration.carriers,
    carrier.virtualPort ∈ ports ∧ carrier.routingPort ∈ ports

lemma step_preserves_port_inventory {configuration : Config} {ports : List Nat}
    (conditions : PortConditions configuration ports)
    {before after : State} {action : Action}
    (step : Step configuration before action after) (present : before.port ∈ ports) :
    after.port ∈ ports := by
  cases step with
  | receive => exact present
  | route route _ _ chosen _ => exact conditions.routeTargets route chosen.1
  | outputRoute route _ _ chosen _ => exact conditions.routeTargets route chosen.1
  | forwardFilter => exact present
  | outputFilter => exact present
  | encryptIPsec => exact present
  | outerRoute route _ _ chosen _ => exact conditions.routeTargets route chosen.1
  | plain => exact present
  | decryptIPsec => exact present
  | inputFilter => exact present
  | deliver => exact present
  | deliverEthernet => exact present
  | wire next _ linked => exact (conditions.physicalEndpoints _ next linked).2
  | bridge next _ linked => exact (conditions.bridgeEndpoints _ next linked).2
  | bridgeOutput next _ linked => exact (conditions.bridgeEndpoints _ next linked).2
  | encryptMACsec port _ configured _ _ _ => exact (conditions.macEndpoints port configured).2
  | unprotectedMACsec port configured _ _ _ _ => exact (conditions.macEndpoints port configured).2
  | decryptMACsec port _ _ _ configured _ _ _ _ _ =>
    exact (conditions.macEndpoints port configured).1
  | uncheckedMACsec port configured _ _ _ => exact (conditions.macEndpoints port configured).1
  | encapsulate port configured _ _ => exact (conditions.carrierEndpoints port configured).2
  | decapsulate port _ configured _ _ _ => exact (conditions.carrierEndpoints port configured).1
  | drop => exact present

theorem all_executions_stay_in_port_inventory {configuration : Config} {ports : List Nat}
    (conditions : PortConditions configuration ports)
    {before after : State} {actions : List Action}
    (run : (lts configuration).MTr before actions after) (present : before.port ∈ ports) :
    after.port ∈ ports := by
  have preserved : (lts configuration).TrInv (fun state => state.port ∈ ports) :=
    fun _ _ _ step member => step_preserves_port_inventory conditions step member
  exact Cslib.LTS.mtrInv_of_trInv preserved _ _ _ run present

end TDN.MultiProtocolExecution
