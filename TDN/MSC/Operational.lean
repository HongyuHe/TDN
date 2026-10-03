import TDN.MSC.Topology

/-!
The observations below provide checked premises for the modeled execution.
Intended topology and configuration are compared with independently captured
interface, routing, policy, SA, and switch records. Required lists must exist;
an empty list cannot satisfy the positive endpoint and policy witnesses.
The statements concern the recorded collection interval. The exporter samples
devices sequentially, so an atomic or future network state remains a separate
assumption for any interpretation involving concurrent execution.
-/
namespace TDN.MSC
open Deployment

def operational? (id : String) : Option TDN.Network.OperationalSnapshot :=
  operationalSnapshots.find? (fun observation => observation.device == id)

def liveInterfaces (id : String) : List TDN.Network.ObservedInterface :=
  ((operational? id).bind TDN.Network.OperationalSnapshot.interfaces).getD []

def liveRoutes (id : String) : List TDN.Network.FibRoute :=
  ((operational? id).bind TDN.Network.OperationalSnapshot.routes).getD []

def livePolicies (id : String) : List TDN.Network.XfrmPolicy :=
  ((operational? id).bind TDN.Network.OperationalSnapshot.policies).getD []

def liveStates (id : String) : List TDN.Network.XfrmState :=
  ((operational? id).bind TDN.Network.OperationalSnapshot.states).getD []

theorem operational_observations_complete :
    (operationalSnapshots.map TDN.Network.OperationalSnapshot.device).Nodup ∧
    ∀ d ∈ devices, ∃ o ∈ operationalSnapshots, o.device = d.id ∧
      o.interfaces.isSome = true ∧ o.routes.isSome = true ∧
      o.routingRules.isSome = true ∧ o.forwarding.isSome = true ∧
      o.policies.isSome = true ∧ o.states.isSome = true := by decide

/-- The exporter queries XFRM on every device. An observed empty host policy
and SA list supplies evidence that local delivery cannot remove an encryption
layer. Missing observations would fail the preceding completeness check. -/
theorem red_hosts_have_no_xfrm : ∀ d ∈ devices, d.role = .host →
    ((operational? d.id).bind TDN.Network.OperationalSnapshot.policies) = some [] ∧
    ((operational? d.id).bind TDN.Network.OperationalSnapshot.states) = some [] := by decide

/-- Each retained port has its declared address and effective MTU and is up.
Addressless switch ports must remain addressless in the observed IPv4 view. -/
theorem observed_interfaces_realize_declaration : ∀ d ∈ devices, ∀ i ∈ d.interfaces,
    ∃ actual ∈ liveInterfaces d.id, actual.name = i.name ∧ actual.mtu = i.mtu ∧
      actual.up = true ∧ actual.carrier = true ∧
      (if i.address.isEmpty then actual.addresses = []
       else actual.addresses.map some = [Prefix.parse? i.address]) := by decide

/-- Extra data interfaces cannot disappear behind the intended port list.
The explicitly recognized internal interfaces are Linux/OVS implementation
interfaces. Management ports were projected out before parsing observations. -/
theorem observed_interfaces_covered : ∀ d ∈ devices, ∀ actual ∈ liveInterfaces d.id,
    actual.name ∈ ["lo", "br0", "ovs-system"] ∨
      ∃ i ∈ d.interfaces, i.name = actual.name := by decide

/-- Both ends independently report the reciprocal veth peer indices. The
host/container observation mechanism supplies the device namespace identity. -/
theorem observed_links_have_reciprocal_peers : ∀ link ∈ links,
    ∃ a ∈ liveInterfaces link.a, ∃ b ∈ liveInterfaces link.b,
      a.name = link.aPort ∧ b.name = link.bPort ∧
      a.peerIndex = some b.index ∧ b.peerIndex = some a.index := by decide

theorem observed_forwarding_matches_roles : ∀ d ∈ devices,
    ((operational? d.id).bind TDN.Network.OperationalSnapshot.forwarding) =
      some (d.role != .host && d.role != .switch && d.role != .admin) := by decide

/-- Every intended static route has a corresponding observed unicast FIB row.
Kernel-connected and OSPF-learned routes remain in the observed record too. -/
theorem declared_static_routes_installed : ∀ d ∈ devices, ∀ route ∈ d.routes,
    ∃ actual ∈ liveRoutes d.id, some actual.destination = Prefix.parse? route.network ∧
      actual.gateway = ipv4? route.via ∧ actual.table = 254 ∧ actual.kind = "unicast" := by decide

theorem observed_route_interfaces_covered : ∀ d ∈ devices, ∀ route ∈ liveRoutes d.id,
    route.output = "lo" ∨ ∃ i ∈ d.interfaces, i.name = route.output := by decide

/-- The selected profile has only ordinary local, optional XFRM, main, and
default lookups. A source-selective or extra policy rule changes the certificate. -/
theorem observed_routing_rules_supported : ∀ o ∈ operationalSnapshots,
    ∀ rule ∈ o.routingRules.getD [], rule.source = ⟨0, 0⟩ ∧
      (rule.priority, rule.table) ∈ [(0, 255), (220, 220), (32766, 254), (32767, 253)] := by decide

/-- Connected and local routes retain their scopes. Next-hop object references
must also carry the expanded output and gateway used by route execution. -/
theorem observed_route_scopes_supported : ∀ d ∈ devices, ∀ route ∈ liveRoutes d.id,
    (route.kind = "local" → route.scope = "host") ∧
    (route.kind = "broadcast" → route.scope = "link") ∧
    (route.kind = "unicast" → route.scope ∈ ["global", "link"]) ∧
    (route.nextHopId.isSome = true → route.gateway.isSome = true ∧ route.output.isEmpty = false) := by decide

def policyAgrees (t : Tunnel) (policy : TDN.Network.XfrmPolicy) : Bool :=
  policy.protocol == "esp" && policy.mode == "tunnel" && policy.reqid == t.reqid &&
    if policy.direction == "out" then
      some policy.source == Prefix.parse? t.localSelector &&
      some policy.destination == Prefix.parse? t.remoteSelector &&
      some policy.tunnelSource == ipv4? t.localAddress &&
      some policy.tunnelDestination == ipv4? t.remoteAddress
    else (policy.direction == "in" || policy.direction == "fwd") &&
      some policy.source == Prefix.parse? t.remoteSelector &&
      some policy.destination == Prefix.parse? t.localSelector &&
      some policy.tunnelSource == ipv4? t.remoteAddress &&
      some policy.tunnelDestination == ipv4? t.localAddress

/-- The policy list covers all three kernel directions and every retained
policy agrees with the declared tunnel. Extra or misbound templates fail. -/
theorem observed_policies_match_tunnels : ∀ t ∈ tunnels,
    (livePolicies t.owner).length = 3 ∧
    (∀ direction ∈ ["in", "out", "fwd"],
      (livePolicies t.owner).any (fun p => p.direction == direction) = true) ∧
    (∀ policy ∈ livePolicies t.owner, policyAgrees t policy = true) := by decide

/-- Every policy can select a sampled SA with its exact tunnel endpoints and
request ID. A nonzero template SPI must agree with that selected SA. Retaining
the SPI prevents a matching endpoint pair from hiding a stale association. -/
theorem observed_policy_spis_select_states : ∀ t ∈ tunnels, ∀ policy ∈ livePolicies t.owner,
    ∃ state ∈ liveStates t.owner, state.source = policy.tunnelSource ∧
      state.destination = policy.tunnelDestination ∧ state.reqid = policy.reqid ∧
      (policy.spi = 0 ∨ policy.spi = state.spi) := by decide

def stateAgrees (t : Tunnel) (state : TDN.Network.XfrmState) : Bool :=
  state.protocol == "esp" && state.mode == "tunnel" && state.reqid == t.reqid &&
    state.algorithm == "rfc4106(gcm(aes))" && state.integrityBits == 128 &&
    (state.flags == 0 || state.flags == 32) &&
    state.tfcPadding == 0 && state.hardLifetimeSeconds > 0 && state.hardLifetimeSeconds ≤ 28800 &&
    ((some state.source == ipv4? t.localAddress && some state.destination == ipv4? t.remoteAddress) ||
     (some state.source == ipv4? t.remoteAddress && some state.destination == ipv4? t.localAddress))

theorem observed_states_match_tunnels : ∀ t ∈ tunnels,
    (∀ state ∈ liveStates t.owner, stateAgrees t state = true) ∧
    (∃ outgoing ∈ liveStates t.owner,
      some outgoing.source = ipv4? t.localAddress ∧ some outgoing.destination = ipv4? t.remoteAddress) ∧
    (∃ incoming ∈ liveStates t.owner,
      some incoming.source = ipv4? t.remoteAddress ∧ some incoming.destination = ipv4? t.localAddress ∧
      incoming.replayWindow > 0) := by decide

/-- Switch bridge state is checked against the declared data ports. NORMAL
switching supplies a conservative adjacency model among those ports. -/
theorem observed_switches_realize_ports : ∀ d ∈ devices, d.role = .switch →
    ∃ o ∈ operationalSnapshots, o.device = d.id ∧
      o.switching.isSome = true ∧
      o.switching.all (fun sw => sw.bridge == "br0" && sw.failMode == "secure" &&
        sw.controllers.isEmpty && sw.normalOnly && !sw.vlanConfigured &&
        sw.ports.length == d.interfaces.length &&
        d.interfaces.all (fun i => sw.ports.contains i.name)) = true := by decide

end TDN.MSC
