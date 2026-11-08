import TDN.Targets.NativeBoundarySpecification
import TDN.Targets.OuterGrayAllowlist

namespace TDN.Targets.Complete
open Compliance

structure RedServiceEndpoint where
  inner : String
  address : Nat
  port : Nat
  protocol : String
  deriving DecidableEq

def RedServiceEndpoint.Bound (endpoint : RedServiceEndpoint) (d : Deployment) : Prop :=
  d.redService endpoint.inner endpoint.address endpoint.port

def ServicePortAtom (source : Bool) (expected : Nat) : PacketPolicy.Atom → Prop
  | .sourcePorts ports => source = true ∧ ∀ port ∈ ports, port = expected
  | .destinationPorts ports => source = false ∧ ∀ port ∈ ports, port = expected
  | _ => False

instance (source : Bool) (expected : Nat) (atom : PacketPolicy.Atom) :
    Decidable (ServicePortAtom source expected atom) := by
  cases atom <;> unfold ServicePortAtom <;> infer_instance

def RedServiceEndpoint.SideGuard (endpoint : RedServiceEndpoint) (source : Bool)
    (rule : PacketPolicy.Rule) : Prop :=
  .protocol endpoint.protocol ∈ rule.atoms ∧
  (if source then .sourceRange endpoint.address endpoint.address ∈ rule.atoms
    else .destinationRange endpoint.address endpoint.address ∈ rule.atoms) ∧
  ((endpoint.protocol ∈ ["icmp", "icmpv6"] ∧ endpoint.port = 0) ∨
    (endpoint.protocol ∈ ["tcp", "udp"] ∧
      ∃ atom ∈ rule.atoms, ServicePortAtom source endpoint.port atom))

instance (endpoint : RedServiceEndpoint) (source : Bool) (rule : PacketPolicy.Rule) :
    Decidable (endpoint.SideGuard source rule) := by
  unfold RedServiceEndpoint.SideGuard
  infer_instance

lemma matching_Red_service_side (d : Deployment) (endpoint : RedServiceEndpoint)
    (bound : endpoint.Bound d) (source : Bool) (rule : PacketPolicy.Rule)
    (guard : endpoint.SideGuard source rule) (packet : PacketPolicy.Packet)
    (matched : rule.toFilter.accepts packet = true) :
    d.redService endpoint.inner
      (if source then packet.source else packet.destination)
      (TransportServicePort packet source) := by
  obtain ⟨protocolAtom, addressAtom, ports⟩ := guard
  have protocol : packet.protocol = endpoint.protocol :=
    PacketPolicy.matching_atom matched protocolAtom
  have address : (if source then packet.source else packet.destination) = endpoint.address := by
    cases source
    · have interval := PacketPolicy.matching_atom matched addressAtom
      change endpoint.address ≤ packet.destination ∧ packet.destination ≤ endpoint.address at interval
      dsimp
      omega
    · have interval := PacketPolicy.matching_atom matched addressAtom
      change endpoint.address ≤ packet.source ∧ packet.source ≤ endpoint.address at interval
      dsimp
      omega
  have port : TransportServicePort packet source = endpoint.port := by
    rcases ports with ⟨control, zero⟩ | ⟨transport, allowed⟩
    · simp [TransportServicePort, protocol, control, zero]
    · have nonControl : packet.protocol ∉ ["icmp", "icmpv6"] := by
        simp only [List.mem_cons, List.mem_singleton] at transport
        rcases transport with transport | transport <;> simp_all
      obtain ⟨portsAtom, atomMember, portGuard⟩ := allowed
      have portMatches := PacketPolicy.matching_atom matched atomMember
      cases portsAtom <;> simp only [ServicePortAtom] at portGuard
      case sourcePorts ports =>
        obtain ⟨rfl, only⟩ := portGuard
        have member : packet.sourcePort ∈ ports := portMatches
        simpa [TransportServicePort, nonControl] using only packet.sourcePort member
      case destinationPorts ports =>
        obtain ⟨rfl, only⟩ := portGuard
        have member : packet.destinationPort ∈ ports := portMatches
        simpa [TransportServicePort, nonControl] using only packet.destinationPort member
  change d.redService endpoint.inner endpoint.address endpoint.port at bound
  simpa only [address, port] using bound

def RedBoundaryRule (device nativeName : String) (direction : Direction)
    (endpoints : List RedServiceEndpoint) (rule : PacketPolicy.Rule) : Prop :=
  RuleMissesHook nativeName direction rule ∨
    ∃ endpoint ∈ endpoints, endpoint.inner = device ∧
      (endpoint.SideGuard true rule ∨ endpoint.SideGuard false rule)

instance (device nativeName : String) (direction : Direction)
    (endpoints : List RedServiceEndpoint) (rule : PacketPolicy.Rule) :
    Decidable (RedBoundaryRule device nativeName direction endpoints rule) := by
  unfold RedBoundaryRule
  infer_instance

lemma matching_Red_boundary_rule (d : Deployment) (device nativeName : String)
    (direction : Direction) (hook : PacketProcessing.Hook)
    (endpoints : List RedServiceEndpoint)
    (bound : ∀ endpoint ∈ endpoints, endpoint.Bound d)
    (rule : PacketPolicy.Rule) (checks : RedBoundaryRule device nativeName direction endpoints rule)
    (packet : PacketPolicy.Packet) (context : PacketAtHook nativeName direction hook packet)
    (matched : rule.toFilter.accepts packet = true) :
    d.redService device packet.source (TransportServicePort packet true) ∨
      d.redService device packet.destination (TransportServicePort packet false) := by
  rcases checks with misses | ⟨endpoint, member, owner, source | destination⟩
  · exact False.elim (hook_mismatch_cannot_match nativeName direction hook packet context rule misses matched)
  · exact Or.inl (owner ▸ matching_Red_service_side d endpoint (bound endpoint member)
      true rule source packet matched)
  · exact Or.inr (owner ▸ matching_Red_service_side d endpoint (bound endpoint member)
      false rule destination packet matched)

end TDN.Targets.Complete
