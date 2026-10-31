import TDN.Semantics.StatefulFilter

namespace TDN.Targets.StatefulDNS

structure Packet where
  source : String
  egress : String
  protocol : String
  destinationPort : Nat
  outbound : Bool

structure LocalAddress where
  address : String
  scopeInterface : Option String
  deriving DecidableEq, Repr

def LocalAddress.matches (binding : LocalAddress) (packet : Packet) : Bool :=
  packet.source == binding.address &&
    binding.scopeInterface.all (fun interface => packet.egress == interface)

structure Guard where
  binding : LocalAddress
  protocol : String
  deriving DecidableEq, Repr

def Guard.toFilter (guard : Guard) : Filter.Rule Packet :=
  ⟨fun packet => packet.outbound && guard.binding.matches packet &&
    packet.protocol == guard.protocol && packet.destinationPort == 53, .deny⟩

def ConventionalLocalRequest (addresses : List LocalAddress) (packet : Packet) : Prop :=
  packet.outbound = true ∧ packet.destinationPort = 53 ∧
  (packet.protocol = "tcp" ∨ packet.protocol = "udp") ∧
  ∃ address ∈ addresses, address.matches packet = true

/-- The captured PF rules use quick denials. Their first-match semantics preserve
the source-address and link-local interface conditions of each expanded rule. -/
def policy (guards : List Guard) : StatefulFilter.Config Packet Unit :=
  { rules := guards.map Guard.toFilter
    fallback := .allow
    key := fun _ => ()
    cachedMatch := fun _ _ => true
    createsState := fun _ => false }

def hookVerdict (enabled : Bool) (skippedInterfaces : List String)
    (guards : List Guard) (cache : List Unit) (packet : Packet) : Filter.Verdict :=
  if enabled && !(skippedInterfaces.contains packet.egress) then
    StatefulFilter.verdict (policy guards) cache packet else .allow

/-- Each local address needs both transports. No finite enumeration of remote
destinations, source ports, packet histories or connection states is needed. -/
theorem local_dns_denied_after_any_history (addresses : List LocalAddress)
    (guards : List Guard)
    (covered : ∀ address ∈ addresses, ∀ protocol ∈ ["tcp", "udp"],
      { binding := address, protocol := protocol } ∈ guards)
    {events : List (Option Packet)} {cache : List Unit}
    (run : (StatefulFilter.lts (policy guards)).MTr [] events cache)
    (packet : Packet) (request : ConventionalLocalRequest addresses packet) :
    StatefulFilter.verdict (policy guards) cache packet = .deny := by
  rw [StatefulFilter.fixed_stateless_policy_is_effective (policy guards) (by intro; rfl) run]
  obtain ⟨outbound, port, transport, address, member, matched⟩ := request
  have protocol : packet.protocol ∈ ["tcp", "udp"] := by
    rcases transport with h | h <;> simp [h]
  have guardMember := covered address member packet.protocol protocol
  have denied : Filter.evaluate (guards.map Guard.toFilter ++ []) .allow packet = .deny := by
    apply Filter.denying_prefix_blocks (guards.map Guard.toFilter) [] .allow packet
    · intro rule listed
      obtain ⟨guard, _, rfl⟩ := List.mem_map.mp listed
      rfl
    · refine ⟨Guard.toFilter { binding := address, protocol := packet.protocol }, ?_, ?_⟩
      · exact List.mem_map.mpr ⟨_, guardMember, rfl⟩
      · simp [Guard.toFilter, outbound, port, matched]
  simpa only [List.append_nil, policy] using denied

/-- Enabled processing on every interface connects the state-cache argument to
the actual egress hook. No initial or future administrative bypass is included. -/
theorem enabled_egress_denies_local_dns (addresses : List LocalAddress)
    (guards : List Guard)
    (covered : ∀ address ∈ addresses, ∀ protocol ∈ ["tcp", "udp"],
      { binding := address, protocol := protocol } ∈ guards)
    {events : List (Option Packet)} {cache : List Unit}
    (run : (StatefulFilter.lts (policy guards)).MTr [] events cache)
    (packet : Packet) (request : ConventionalLocalRequest addresses packet) :
    hookVerdict true [] guards cache packet = .deny := by
  simpa [hookVerdict] using local_dns_denied_after_any_history addresses guards covered run packet request

end TDN.Targets.StatefulDNS
