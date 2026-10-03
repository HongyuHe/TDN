import TDN.MSC.Execution
import TDN.Network.Hardening

/-!
The retained hardening obligations are SR-20's explicit DNS alternative,
SR-21's disabled remote boot configuration, OR-8's routing-protocol restriction,
and PF-2's disabled unused interfaces. The observations include startup and
resolver configuration from every container sharing the device namespace.
Namespace-wide process sampling includes FRR control sidecars.

The selected DNS branch permits the existing CloudLab resolver address. DNS
disabling under optional SR-19 is not silently made mandatory. These statements
concern recorded configuration and its modeled execution. The trusted container
runtime, command interpretation, and shared worker clock remain explicit
implementation assumptions. Optional management is projected out upstream.
-/
namespace TDN.MSC.Hardening
open Deployment TDN.Network.Hardening

def appliances : List ApplianceObservation := applianceObservations.filterMap id

def hasFRRControl (device : Device) : Bool :=
  device.role == .transport || device.role == .firewall || device.role == .grayFirewall

def expectedContainers (device : Device) : List String :=
  [device.id] ++ if hasFRRControl device then [device.id ++ "-frr"] else []

/-- Missing observations and unknown namespace participants cannot disappear
behind an empty successful inventory. The role declaration supplies the expected
containers independently of the live namespace scan. -/
theorem appliance_observations_complete :
    applianceObservations.all Option.isSome = true ∧
    (appliances.map ApplianceObservation.device).Nodup ∧
    ∀ device ∈ devices, ∃ observation ∈ appliances,
      observation.device = device.id ∧
      observation.processes.isEmpty = false ∧
      (observation.containers.map StartupContainer.name).Perm (expectedContainers device) := by decide

theorem startup_programs_are_local : ∀ observation ∈ appliances,
    ∀ container ∈ observation.containers, localStartup container.program = true := by decide

/-- Concrete command checks supply the premise of the reusable trace theorem.
The conclusion concerns every execution of each captured startup program. -/
theorem retained_startup_never_fetches_remote_configuration
    (observation : ApplianceObservation) (member : observation ∈ appliances)
    (container : StartupContainer) (included : container ∈ observation.containers)
    (effects : List StartupEffect) (execution : StartupTrace container.program effects) :
    ∀ effect ∈ effects, effect = .local :=
  local_startup_has_no_network_configuration
    (startup_programs_are_local observation member container included) execution

/-- 130.127.132.51 is the explicitly selected existing CloudLab resolver.
The policy is a separate constant, so adding a resolver to observations changes
the certificate rather than silently extending the accepted policy. -/
def selectedDNSServers : List UInt32 := [2189394995]

def selectedDNSPolicy : DNSPolicy := .specified selectedDNSServers

theorem resolver_settings_match_selected_policy : ∀ observation ∈ appliances,
    ∀ container ∈ observation.containers,
      selectedDNSPolicy.accepts container.resolver = true := by decide

theorem retained_resolver_queries_use_selected_servers
    (observation : ApplianceObservation) (member : observation ∈ appliances)
    (container : StartupContainer) (included : container ∈ observation.containers)
    (address : UInt32) (query : address ∈ container.resolver.servers) :
    address ∈ selectedDNSServers :=
  specified_dns_queries_target_selected_servers selectedDNSServers container.resolver
    (resolver_settings_match_selected_policy observation member container included) address query

/-- Every declared data port is used by an observed-and-checked virtual link.
Loopback and the OVS bridge/kernel device have explicit implementation roles.
An extra port does not acquire a purpose merely by appearing in an observation. -/
def usedInterfaces (device : Device) : List String :=
  ["lo"] ++ links.flatMap (fun link =>
    (if link.a == device.id then [link.aPort] else []) ++
    (if link.b == device.id then [link.bPort] else [])) ++
    if device.role == .switch then ["br0", "ovs-system"] else []

theorem enabled_interfaces_have_a_declared_use : ∀ device ∈ devices,
    (liveInterfaces device.id).all (interfaceUsed (usedInterfaces device)) = true := by decide

theorem retained_unused_interface_is_disabled (device : Device) (member : device ∈ devices)
    (port : TDN.Network.ObservedInterface) (observed : port ∈ liveInterfaces device.id)
    (unused : port.name ∉ usedInterfaces device) : port.up = false :=
  unused_interface_is_disabled (usedInterfaces device) (liveInterfaces device.id)
    (enabled_interfaces_have_a_declared_use device member) port observed unused

/-- The executable path and comm name are both retained. Absence of these
daemons is a sampled software fact. Arbitrary code masquerading as another
program remains outside the trusted process-classification boundary. -/
def routingDaemons : List String :=
  ["bgpd", "ospfd", "ospf6d", "ripd", "ripngd", "isisd", "pimd", "pim6d",
   "ldpd", "nhrpd", "eigrpd", "babeld", "fabricd", "bird", "bird6", "routed", "mrouted", "xorp_rtrmgr"]

def routingProcess (process : NamespaceProcess) : Bool :=
  routingDaemons.contains process.name ||
    routingDaemons.any (fun daemon =>
      process.executable.toList.reverse.take (daemon.toList.length + 1) == ("/" ++ daemon).toList.reverse)

theorem outer_namespaces_have_no_routing_daemon : ∀ device ∈ devices, device.role = .outer →
    ∀ observation ∈ appliances, observation.device = device.id →
      observation.processes.all (fun process => !routingProcess process) = true := by decide

/-- External locally sourced or terminated OSPF and TCP-based BGP cannot pass
the imported gateway chains. Encrypted transit payloads are a separate case,
so the statement does not prohibit approved forwarding through an outer. -/
theorem external_gateway_local_traffic_excludes_ospf_and_bgp
    (contract : LocalContract) (member : contract ∈ localContracts)
    (direction : LocalDirection) (packet : RoutedPacket)
    (external : LocalContract.interface direction packet ≠ "lo")
    (accepted : localDecision direction contract.device packet = some true) :
    packet.protocol ≠ 89 ∧ packet.protocol ≠ 6 := by
  have peer := accepted_external_local_packet_is_declared_control
    contract member direction packet external accepted
  have ipsec : ipsecClass packet = true := by
    simp only [LocalContract.peerAllows, Bool.and_eq_true] at peer
    exact peer.2
  simp only [ipsecClass, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq] at ipsec
  rcases ipsec with esp | udp
  · simp [← esp]
  · simp [← udp.1]

/-- The container wall clock falls within the enclosing worker sample, and
the worker reports NTP synchronization. Authenticity and accuracy of the NTP
source remain trusted; the Boolean alone is not a proof of UTC correctness. -/
theorem sampled_appliance_clocks_agree_with_synchronized_worker :
    ∀ observation ∈ appliances, observation.ntpSynchronized = true ∧
      observation.workerBefore ≤ observation.deviceClock ∧
      observation.deviceClock ≤ observation.workerAfter ∧
      observation.workerAfter ≤ observation.workerBefore + 30 := by decide

end TDN.MSC.Hardening
