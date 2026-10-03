import TDN.MSC.Authentication
import TDN.MSC.ExecutionTrace
import TDN.MSC.FirewallControl
import TDN.MSC.Hardening
import TDN.Network.Services

/-!
The selected service arrangement uses literal IKE endpoints, loaded local CRLs,
permanent IPv4 addresses, and the shared worker clock. The configuration comes
from hashed service files. Public retrieval metadata, loaded authority entries,
address lifetimes, and namespace process observations check that arrangement.

Every declared inner peer exchange receives positive routed witnesses, as does
each declared Red-host direction. The witnesses evaluate the imported filters,
routes, XFRM state, and virtual links. Next-hop checks also require each routed
leg to reach the address selected by its actual FIB lookup. Those selected
paths avoid Gray Firewalls, which explains the empty required Gray transit set
in the deployed separate-Gray layout. Shared-Gray layouts need other witnesses
and nonempty firewall allowances. Optional management contributes no condition.
-/
namespace TDN.MSC.ControlServices
set_option synthInstance.maxSize 1024
open Deployment
open TDN.Network (IPv4Header WirePacket CredentialAudit AuthenticationObservation)
open TDN.Network.Execution
open TDN.Network.Services
open TDN.MSC.Execution TDN.MSC.ExecutionTrace

def authorities (owner : String) :=
  (Authentication.observation? owner).bind AuthenticationObservation.authorities

theorem service_configurations_cover_tunnels : ∀ tunnel ∈ tunnels,
    ∃ config ∈ serviceConfigurations, config.device = tunnel.owner ∧
      some config.localAddress = ipv4? tunnel.localAddress ∧
      some config.peerAddress = ipv4? tunnel.remoteAddress ∧
      config.externalInterface = (if role? tunnel.owner = some .inner then "gray" else "black") := by decide

theorem selected_service_mechanisms_are_declared : ∀ config ∈ serviceConfigurations,
    config.localProtocols = ["esp", "udp/500", "udp/4500"] ∧
      config.revocationDelivery = "local CRL files" ∧ config.clock = "shared worker kernel" := by decide

/-- Required observations must be present before an empty retrieval set can
be interpreted. Every public object contributes its advertised locations. -/
theorem revocation_retrieval_sets_are_observed_empty : ∀ tunnel ∈ tunnels,
    (Authentication.audit? tunnel.owner).isSome = true ∧ (authorities tunnel.owner).isSome = true ∧
    ∀ audit ∈ (Authentication.audit? tunnel.owner).toList,
      retrievalLocations? audit (authorities tunnel.owner) = some [] := by decide

/-- PF-25's local-CRL branch is tied to the admission checker. Any accepted
request uses a loaded, current CRL and an unrevoked certificate; no advertised
network retrieval is needed by the selected credential arrangement. -/
theorem admitted_peer_has_local_revocation_evidence (tunnel : Tunnel) (member : tunnel ∈ tunnels)
    (audit : CredentialAudit) (captured : audit ∈ (Authentication.audit? tunnel.owner).toList)
    (request : TDN.Network.Authentication.Request)
    (accepted : TDN.Network.Authentication.admits (Authentication.policy tunnel.owner) audit request = true) :
    retrievalLocations? audit (authorities tunnel.owner) = some [] ∧
    ∃ certificate ∈ audit.certificates, ∃ crl ∈ audit.crls,
      certificate.fingerprint = request.certificate ∧
      certificate.notBefore ≤ audit.atEpoch ∧ audit.atEpoch ≤ certificate.notAfter ∧
      crl.thisUpdate ≤ audit.atEpoch ∧ audit.atEpoch < crl.nextUpdate ∧
      certificate.serial ∉ crl.revokedSerials :=
  local_revocation_supports_admitted_request (Authentication.policy tunnel.owner) audit
    (authorities tunnel.owner) ((revocation_retrieval_sets_are_observed_empty tunnel member).2.2 audit captured)
    request accepted

/-- The permanent lifetime value is the kernel's IPv4 infinity sentinel.
Observed permanent addresses support the static-addressing service choice.
Missing lifetime metadata cannot satisfy the finite certificate. -/
theorem retained_ipv4_addresses_are_permanent : ∀ device ∈ devices,
    ∀ port ∈ liveInterfaces device.id, ∃ metadata ∈ port.addressMetadata.toList,
      metadata.map TDN.Network.AddressMetadata.network = port.addresses ∧
      ∀ address ∈ metadata, address.dynamic = false ∧
        address.validLifetime = 4294967295 ∧ address.preferredLifetime = 4294967295 := by decide

def timeAddressPrograms : List String :=
  ["ntpd", "chronyd", "systemd-timesyncd", "dhclient", "dhcpcd", "udhcpc", "dhcpd", "dnsmasq"]

def timeAddressProcess (process : TDN.Network.Hardening.NamespaceProcess) : Bool :=
  timeAddressPrograms.contains process.name || timeAddressPrograms.any (fun name =>
    process.executable.toList.reverse.take (name.toList.length + 1) == ("/" ++ name).toList.reverse)

/-- The namespace-wide scan includes sidecars. The result supports the chosen
worker-clock and static-address mechanisms at the sampled time. Trusted process
classification and future operator changes remain explicit boundaries. -/
theorem retained_namespaces_have_no_time_or_address_client : ∀ observation ∈ Hardening.appliances,
    observation.processes.all (fun process => !timeAddressProcess process) = true := by decide

/-- OSPF control grants belong to declared Black links. Their required local
allowances were checked separately; they create no Gray Firewall demand. -/
theorem ospf_control_uses_black_interfaces : ∀ adjacency ∈ FirewallControl.adjacencies,
    ∃ device ∈ devices, device.id = adjacency.owner ∧ device.role = .firewall ∧
      ∃ port ∈ device.interfaces, port.name = adjacency.interface ∧ port.zone = .black := by decide

structure Plan where
  source : String
  target : String
  targetPort : String
  servicePort : Nat
  start : State String Unit
  commands : List Command
  deriving DecidableEq, BEq, Repr

def innerPlans : List Plan := tunnels.flatMap fun tunnel =>
  if role? tunnel.owner != some .inner then [] else
  witnessedPairs.flatMap fun choice =>
    if tunnel.owner != "I_" ++ choice.1 ++ choice.2.2 ||
        tunnel.peer != "I_" ++ choice.2.1 ++ choice.2.2 then [] else
    [500, 4500].map fun port =>
      let commands := dataCommands choice.1 choice.2.1 choice.2.2
      let header : IPv4Header :=
        { source := (ipv4? tunnel.localAddress).getD 0,
          destination := (ipv4? tunnel.remoteAddress).getD 0,
          protocol := 17, destinationPort := port, bytes := 100 }
      { source := tunnel.owner, target := tunnel.peer, targetPort := "gray", servicePort := port,
        start := ⟨⟨tunnel.owner, "gray"⟩, .output, .clear header none⟩,
        commands := (commands.drop 2).take (commands.length - 4) }

def dataPlans : List Plan := witnessedPairs.map fun choice =>
  let source := "R_" ++ choice.1 ++ choice.2.2
  let target := "R_" ++ choice.2.1 ++ choice.2.2
  { source := source, target := target, targetPort := "red", servicePort := 0,
    start := start source target, commands := dataCommands choice.1 choice.2.1 choice.2.2 }

def plans : List Plan := innerPlans ++ dataPlans

/-- Every declared inner peer has both IKE port witnesses. The finite coverage
check prevents a missing or renamed peer from disappearing from the path set. -/
theorem inner_service_demands_have_plans : ∀ tunnel ∈ tunnels, role? tunnel.owner = some .inner →
    ∀ port ∈ [500, 4500], ∃ plan ∈ innerPlans,
      plan.source = tunnel.owner ∧ plan.target = tunnel.peer ∧ plan.servicePort = port ∧
      some plan.start.packet.header.source = ipv4? tunnel.localAddress ∧
      some plan.start.packet.header.destination = ipv4? tunnel.remoteAddress := by decide

theorem red_data_demands_have_plans : ∀ pair ∈ authorizedHostPairs,
    ∃ plan ∈ dataPlans, plan.source = pair.1 ∧ plan.target = pair.2 := by decide

/-- Each selected service can leave its source and reach its intended peer's
INPUT policy. Every routed leg follows the observed next hop. The footprint
contains all intermediate states, including switches and encryptors. -/
theorem selected_service_paths_checked : ∀ plan ∈ plans,
    model.outputFilter plan.start.location.node plan.start.location.port plan.start.packet.header = true ∧
    (trace plan.start plan.commands).isSome = true ∧
    ∀ result ∈ (trace plan.start plan.commands).toList,
      result.last.location = ⟨plan.target, plan.targetPort⟩ ∧ result.last.phase = .input ∧
      (model.deliver plan.target plan.targetPort result.last.packet).isSome = true ∧
      respectsNextHops model (plan.start :: result.visited) = true ∧
      ∀ state ∈ plan.start :: result.visited, role? state.location.node ≠ some .grayFirewall := by decide

/-- The empty Gray transit set is derived from successful routed executions.
An unavailable trace yields `none`, which cannot masquerade as an empty set. -/
def requiredGrayTransits? : Option (List String) := do
  let footprints ← plans.mapM fun plan => do
    let result ← trace plan.start plan.commands
    pure ((plan.start :: result.visited).filterMap fun state =>
      if role? state.location.node == some .grayFirewall then some state.location.node else none)
  pure footprints.flatten

theorem selected_services_require_no_gray_transit : requiredGrayTransits? = some [] := by decide

/-- A general runner theorem turns the finite positive certificate into a
real path of the execution relation that avoids Gray Firewalls. The next-hop
certificate and peer INPUT check remain visible in the conclusion. -/
theorem required_service_has_executable_gray_free_path (plan : Plan) (member : plan ∈ plans) :
    ∃ result : TDN.Network.ExecutionTrace.Result String Unit, TDN.Network.Reach
      (TDN.Network.Without (Step model) (fun state => role? state.location.node = some .grayFirewall))
      plan.start result.last ∧
      result.last.location = ⟨plan.target, plan.targetPort⟩ ∧ result.last.phase = .input ∧
      (model.deliver plan.target plan.targetPort result.last.packet).isSome = true ∧
      respectsNextHops model (plan.start :: result.visited) = true := by
  have certificate := selected_service_paths_checked plan member
  cases found : trace plan.start plan.commands with
  | none => simp [found] at certificate
  | some result =>
    obtain ⟨target, phase, delivered, coherent, absent⟩ := certificate.2.2 result (by simp [found])
    exact ⟨result,
      TDN.Network.ExecutionTrace.checked_trace_avoids model
        (fun state => role? state.location.node = some .grayFirewall) plan.start plan.commands result found absent,
      target, phase, delivered, coherent⟩

end TDN.MSC.ControlServices
