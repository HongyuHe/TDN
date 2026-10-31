import TDN.Semantics.PacketPolicy
import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.KernelResponses

/-- Echo replies and error quotes both copy bytes from an existing packet.
The pending response retains that source state for payload/protection provenance.
No assumption about whether generation precedes INPUT or FORWARD is needed. -/
inductive Kind where
  | echo | errorQuote
  deriving DecidableEq, Repr

def ResponseProtocol (protocol : String) : Prop :=
  protocol = "icmp" ∨ protocol = "ipv6-icmp"

instance (protocol : String) : Decidable (ResponseProtocol protocol) := by
  unfold ResponseProtocol
  infer_instance

/-- An allow rule either restricts output to loopback or names a protocol
outside the kernel-response class. This finite syntactic check is sufficient,
without assuming any packet's desired global protection property. -/
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

/-- Ordered rules with default denial confine every kernel-response protocol
to loopback, regardless of source/destination fields or copied content. -/
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

/-- The response copies from source. Header bytes may be changed arbitrarily
within ICMP/ICMPv6, which conservatively includes echo and all error quotes. -/
inductive State (NetworkState : Type) where
  | network (state : NetworkState)
  | generated (source : NetworkState) (kind : Kind) (header : PacketPolicy.Packet)
  | routed (source : NetworkState) (kind : Kind) (header : PacketPolicy.Packet) (port : Nat)
  | consumed

inductive Action (NetworkAction : Type) where
  | network (action : NetworkAction)
  | generate | route | emit | consume

/-- The hook sees the actual selected output interface. A concrete application
binds routing, enabled generators and rules to the same captured device.
emit reconstructs the copied-body response, preserving its source provenance. -/
structure Config (NetworkState : Type) where
  generates : NetworkState → Prop
  selectedRoute : NetworkState → PacketPolicy.Packet → Nat → Prop
  outputRules : NetworkState → Nat → List PacketPolicy.Rule
  outputFallback : NetworkState → Nat → Filter.Verdict
  interfaceName : Nat → String
  emit : NetworkState → PacketPolicy.Packet → Nat → NetworkState

def outputPacket {S : Type} (config : Config S) (header : PacketPolicy.Packet) (port : Nat) :
    PacketPolicy.Packet :=
  { header with egress := config.interfaceName port, inboundPolicies := [] }

inductive Step {S A : Type} (network : Cslib.LTS S A) (config : Config S) :
    State S → Action A → State S → Prop
  | network {before after : S} {action : A} (step : network.Tr before action after) :
      Step network config (.network before) (.network action) (.network after)
  | generate (source : S) (kind : Kind) (header : PacketPolicy.Packet)
      (enabled : config.generates source) (protocol : ResponseProtocol header.protocol) :
      Step network config (.network source) .generate (.generated source kind header)
  | route (source : S) (kind : Kind) (header : PacketPolicy.Packet) (port : Nat)
      (chosen : config.selectedRoute source header port) :
      Step network config (.generated source kind header) .route (.routed source kind header port)
  | emit (source : S) (kind : Kind) (header : PacketPolicy.Packet) (port : Nat)
      (accepted : Filter.evaluate
        ((config.outputRules source port).map PacketPolicy.Rule.toFilter) (config.outputFallback source port)
        (outputPacket config header port) = .allow)
      (external : config.interfaceName port ≠ "lo") :
      Step network config (.routed source kind header port) .emit
        (.network (config.emit source header port))
  | consume (state : State S) : Step network config state .consume .consumed

def lts {S A : Type} (network : Cslib.LTS S A) (config : Config S) :
    Cslib.LTS (State S) (Action A) := ⟨Step network config⟩

def Invariant {S : Type} (config : Config S) (safe : S → Prop) : State S → Prop
  | .network state => safe state
  | .generated source _ header | .routed source _ header _ =>
      config.generates source ∧ ResponseProtocol header.protocol
  | .consumed => True

/-- Rule-local OUTPUT checks preserve an existing network safety invariant
when kernel responses are added at arbitrary enabled processing points.
Generation and routing are modeled explicitly; no response can escape to
a non-loopback interface under these checked rules. -/
lemma response_output_guards_preserve_network_invariant {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (checked : ∀ source, config.generates source → ∀ port,
      config.outputFallback source port = .deny ∧
      ∀ rule ∈ config.outputRules source port,
        rule.verdict = .allow → SafeResponseRule rule) :
    (lts network config).TrInv (Invariant config safe) := by
  intro before action after step valid
  cases step with
  | network step => exact networkPreserves _ _ _ step valid
  | generate source kind header enabled protocol => exact ⟨enabled, protocol⟩
  | route => exact valid
  | emit source kind header port accepted external =>
    obtain ⟨fallback, rules⟩ := checked source valid.1 port
    rw [fallback] at accepted
    exact False.elim (external (accepted_response_is_loopback (config.outputRules source port)
      rules (outputPacket config header port) valid.2 accepted))
  | consume => trivial

theorem network_observations_remain_safe_with_kernel_responses {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (checked : ∀ source, config.generates source → ∀ port,
      config.outputFallback source port = .deny ∧
      ∀ rule ∈ config.outputRules source port,
        rule.verdict = .allow → SafeResponseRule rule)
    {before after : S} {actions : List (Action A)}
    (run : (lts network config).MTr (.network before) actions (.network after))
    (initial : safe before) : safe after :=
  Cslib.LTS.mtrInv_of_trInv
    (response_output_guards_preserve_network_invariant network config safe networkPreserves checked)
    (.network before) actions (.network after) run initial


/-- Pending copied-byte responses retain their triggering network state's
safety facts. The routed case also retains the actual route relation. -/
def ProvenanceInvariant {S : Type} (config : Config S) (safe : S → Prop) : State S → Prop
  | .network state => safe state
  | .generated source _ header =>
      safe source ∧ config.generates source ∧ ResponseProtocol header.protocol
  | .routed source _ header port =>
      safe source ∧ config.generates source ∧ ResponseProtocol header.protocol ∧
        config.selectedRoute source header port
  | .consumed => True

/-- Replies may be emitted when local ingress, association, route and OUTPUT
checks establish that their copied bytes retain the required protection.
The assumption is local to one emission; CSLib supplies the execution proof. -/
lemma local_reply_checks_preserve_network_safety {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (replyPreserves : ∀ source header port,
      safe source → config.generates source → ResponseProtocol header.protocol →
      config.selectedRoute source header port →
      Filter.evaluate ((config.outputRules source port).map PacketPolicy.Rule.toFilter)
        (config.outputFallback source port) (outputPacket config header port) = .allow →
      config.interfaceName port ≠ "lo" → safe (config.emit source header port)) :
    (lts network config).TrInv (ProvenanceInvariant config safe) := by
  intro before action after step valid
  cases step with
  | network step => exact networkPreserves _ _ _ step valid
  | generate source kind header enabled protocol => exact ⟨valid, enabled, protocol⟩
  | route source kind header port selected => exact ⟨valid.1, valid.2.1, valid.2.2, selected⟩
  | emit source kind header port accepted external =>
    exact replyPreserves source header port valid.1 valid.2.1 valid.2.2.1 valid.2.2.2 accepted external
  | consume => trivial

theorem copied_response_executions_remain_safe {S A : Type}
    (network : Cslib.LTS S A) (config : Config S) (safe : S → Prop)
    (networkPreserves : network.TrInv safe)
    (replyPreserves : ∀ source header port,
      safe source → config.generates source → ResponseProtocol header.protocol →
      config.selectedRoute source header port →
      Filter.evaluate ((config.outputRules source port).map PacketPolicy.Rule.toFilter)
        (config.outputFallback source port) (outputPacket config header port) = .allow →
      config.interfaceName port ≠ "lo" → safe (config.emit source header port))
    {before after : S} {actions : List (Action A)}
    (run : (lts network config).MTr (.network before) actions (.network after))
    (initial : safe before) : safe after :=
  Cslib.LTS.mtrInv_of_trInv
    (local_reply_checks_preserve_network_safety network config safe networkPreserves replyPreserves)
    (.network before) actions (.network after) run initial

end TDN.KernelResponses
