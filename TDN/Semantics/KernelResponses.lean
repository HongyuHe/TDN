import TDN.Semantics.PacketPolicy
import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.KernelResponses

inductive Kind where
  | echo | errorQuote
  deriving DecidableEq, Repr

def ResponseProtocol (protocol : String) : Prop :=
  protocol = "icmp" ∨ protocol = "ipv6-icmp"

instance (protocol : String) : Decidable (ResponseProtocol protocol) := by
  unfold ResponseProtocol
  infer_instance

def SafeResponseRule (rule : PacketPolicy.Rule) : Prop :=
  PacketPolicy.Atom.egress "lo" ∈ rule.atoms ∨
  ∃ atom ∈ rule.atoms, match atom with
    | .protocol name => ¬ ResponseProtocol name
    | _ => False

instance (rule : PacketPolicy.Rule) : Decidable (SafeResponseRule rule) := by
  unfold SafeResponseRule
  letI (atom : PacketPolicy.Atom) : Decidable
      (match atom with | .protocol name => ¬ ResponseProtocol name | _ => False) := by
    cases atom <;> infer_instance
  infer_instance

theorem accepted_response_is_loopback (rules : List PacketPolicy.Rule)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → SafeResponseRule rule)
    (packet : PacketPolicy.Packet) (response : ResponseProtocol packet.protocol)
    (accepted : Filter.evaluate (rules.map PacketPolicy.Rule.toFilter) .deny packet = .allow) :
    packet.egress = "lo" := by
  obtain ⟨rule, member, matched, allows⟩ := Filter.allowed_has_matching_allow _ packet accepted
  obtain ⟨original, inRules, rfl⟩ := List.mem_map.mp member
  rcases checked original inRules allows with loopback | ⟨atom, inAtoms, excludes⟩
  · exact PacketPolicy.matching_atom matched loopback
  · have holds := PacketPolicy.matching_atom matched inAtoms
    cases atom <;> simp only at excludes <;> try contradiction
    case protocol name =>
      exact False.elim (excludes (holds ▸ response))

inductive State (NetworkState : Type) where
  | network (state : NetworkState)
  | generated (source : NetworkState) (kind : Kind) (header : PacketPolicy.Packet)
  | routed (source : NetworkState) (kind : Kind) (header : PacketPolicy.Packet) (iface : Nat)
  | consumed

inductive Action (NetworkAction : Type) where
  | network (action : NetworkAction)
  | generate | route | emit | consume

structure Config (NetworkState : Type) where
  generates : NetworkState → Prop
  selectedRoute : NetworkState → PacketPolicy.Packet → Nat → Prop
  outputRules : NetworkState → Nat → List PacketPolicy.Rule
  outputFallback : NetworkState → Nat → Filter.Verdict
  interfaceName : Nat → String
  emit : NetworkState → PacketPolicy.Packet → Nat → NetworkState

def outputPacket {S : Type} (config : Config S) (header : PacketPolicy.Packet) (iface : Nat) :
    PacketPolicy.Packet :=
  { header with egress := config.interfaceName iface, inboundPolicies := [] }

inductive Step {S A : Type} (network : Cslib.LTS S A) (config : Config S) :
    State S → Action A → State S → Prop
  | network {before after : S} {action : A} (step : network.Tr before action after) :
      Step network config (.network before) (.network action) (.network after)
  | generate (source : S) (kind : Kind) (header : PacketPolicy.Packet)
      (enabled : config.generates source) (protocol : ResponseProtocol header.protocol) :
      Step network config (.network source) .generate (.generated source kind header)
  | route (source : S) (kind : Kind) (header : PacketPolicy.Packet) (iface : Nat)
      (chosen : config.selectedRoute source header iface) :
      Step network config (.generated source kind header) .route (.routed source kind header iface)
  | emit (source : S) (kind : Kind) (header : PacketPolicy.Packet) (iface : Nat)
      (accepted : Filter.evaluate
        ((config.outputRules source iface).map PacketPolicy.Rule.toFilter) (config.outputFallback source iface)
        (outputPacket config header iface) = .allow)
      (external : config.interfaceName iface ≠ "lo") :
      Step network config (.routed source kind header iface) .emit
        (.network (config.emit source header iface))
  | consume (state : State S) : Step network config state .consume .consumed

def lts {S A : Type} (network : Cslib.LTS S A) (config : Config S) :
    Cslib.LTS (State S) (Action A) := ⟨Step network config⟩

def Invariant {S : Type} (config : Config S) (safe : S → Prop) : State S → Prop
  | .network state => safe state
  | .generated source _ header | .routed source _ header _ =>
      config.generates source ∧ ResponseProtocol header.protocol
  | .consumed => True

lemma response_output_guards_preserve_network_invariant {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (checked : ∀ source, config.generates source → ∀ iface,
      config.outputFallback source iface = .deny ∧
      ∀ rule ∈ config.outputRules source iface,
        rule.verdict = .allow → SafeResponseRule rule) :
    (lts network config).TrInv (Invariant config safe) := by
  intro before action after step valid
  cases step with
  | network step => exact networkPreserves _ _ _ step valid
  | generate source kind header enabled protocol => exact ⟨enabled, protocol⟩
  | route => exact valid
  | emit source kind header iface accepted external =>
    obtain ⟨fallback, rules⟩ := checked source valid.1 iface
    rw [fallback] at accepted
    exact False.elim (external (accepted_response_is_loopback (config.outputRules source iface)
      rules (outputPacket config header iface) valid.2 accepted))
  | consume => trivial

theorem network_observations_remain_safe_with_kernel_responses {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (checked : ∀ source, config.generates source → ∀ iface,
      config.outputFallback source iface = .deny ∧
      ∀ rule ∈ config.outputRules source iface,
        rule.verdict = .allow → SafeResponseRule rule)
    {before after : S} {actions : List (Action A)}
    (run : (lts network config).MTr (.network before) actions (.network after))
    (initial : safe before) : safe after :=
  Cslib.LTS.mtrInv_of_trInv
    (response_output_guards_preserve_network_invariant network config safe networkPreserves checked)
    (.network before) actions (.network after) run initial

def ProvenanceInvariant {S : Type} (config : Config S) (safe : S → Prop) : State S → Prop
  | .network state => safe state
  | .generated source _ header =>
      safe source ∧ config.generates source ∧ ResponseProtocol header.protocol
  | .routed source _ header iface =>
      safe source ∧ config.generates source ∧ ResponseProtocol header.protocol ∧
        config.selectedRoute source header iface
  | .consumed => True

lemma local_reply_checks_preserve_network_safety {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (replyPreserves : ∀ source header iface,
      safe source → config.generates source → ResponseProtocol header.protocol →
      config.selectedRoute source header iface →
      Filter.evaluate ((config.outputRules source iface).map PacketPolicy.Rule.toFilter)
        (config.outputFallback source iface) (outputPacket config header iface) = .allow →
      config.interfaceName iface ≠ "lo" → safe (config.emit source header iface)) :
    (lts network config).TrInv (ProvenanceInvariant config safe) := by
  intro before action after step valid
  cases step with
  | network step => exact networkPreserves _ _ _ step valid
  | generate source kind header enabled protocol => exact ⟨valid, enabled, protocol⟩
  | route source kind header iface selected => exact ⟨valid.1, valid.2.1, valid.2.2, selected⟩
  | emit source kind header iface accepted external =>
    exact replyPreserves source header iface valid.1 valid.2.1 valid.2.2.1 valid.2.2.2 accepted external
  | consume => trivial

theorem copied_response_executions_remain_safe {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (replyPreserves : ∀ source header iface,
      safe source → config.generates source → ResponseProtocol header.protocol →
      config.selectedRoute source header iface →
      Filter.evaluate ((config.outputRules source iface).map PacketPolicy.Rule.toFilter)
        (config.outputFallback source iface) (outputPacket config header iface) = .allow →
      config.interfaceName iface ≠ "lo" → safe (config.emit source header iface))
    {before after : S} {actions : List (Action A)}
    (run : (lts network config).MTr (.network before) actions (.network after))
    (initial : safe before) : safe after :=
  Cslib.LTS.mtrInv_of_trInv
    (local_reply_checks_preserve_network_safety network config safe networkPreserves replyPreserves)
    (.network before) actions (.network after) run initial

end TDN.KernelResponses
