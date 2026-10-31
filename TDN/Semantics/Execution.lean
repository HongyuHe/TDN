import Cslib.Foundations.Semantics.LTS.Simulation
import TDN.Semantics.PacketPolicy
import TDN.Semantics.InternetAddresses

namespace TDN.Execution

structure Seal where
  tag : Nat
  association : Nat
  sender : Nat
  receiver : Nat
  deriving DecidableEq, Repr

structure Envelope where
  authentication : Seal
  header : PacketPolicy.Packet

structure Frame where
  payload : Nat
  originDomain : Nat
  packet : PacketPolicy.Packet
  envelopes : List Envelope
  enteredPort : Nat := 0

def payloadAddresses (packet : PacketPolicy.Packet) : List Envelope → Nat × Nat
  | [] => (packet.source, packet.destination)
  | envelope :: rest => payloadAddresses envelope.header rest

def Frame.addresses (frame : Frame) : Nat × Nat :=
  payloadAddresses frame.packet frame.envelopes

lemma payload_addresses_ignore_metadata {a b : PacketPolicy.Packet} (envelopes : List Envelope)
    (source : a.source = b.source) (destination : a.destination = b.destination) :
    payloadAddresses a envelopes = payloadAddresses b envelopes := by
  cases envelopes with
  | nil => exact Prod.ext source destination
  | cons => rfl

inductive Phase where
  | received | ingress | localOutput | routed | outputRouted
  | filtered | encapsulated | ready | localInput | delivered | dropped
  deriving DecidableEq, Repr

structure State where
  port : Nat
  phase : Phase
  frame : Frame
  authenticated : List Nat

structure Association where
  id : Nat
  tag : Nat
  sender : Nat
  receiver : Nat
  sourceLow : Nat
  sourceHigh : Nat
  destinationLow : Nat
  destinationHigh : Nat
  priority : Nat
  templateSPI : Option Nat := none
  deriving DecidableEq, Repr

structure SecurityAssociation where
  localRequestId : Nat
  wireIdentity : Nat
  sender : Nat
  receiver : Nat
  deriving DecidableEq, Repr

def StateBindsPolicy (state : SecurityAssociation) (policy : Association) : Prop :=
  state.localRequestId = policy.id ∧ state.sender = policy.sender ∧
  state.receiver = policy.receiver ∧
  (policy.templateSPI = none ∨ policy.templateSPI = some state.wireIdentity)

def Association.seal (a : Association) (state : SecurityAssociation) : Seal :=
  ⟨a.tag, state.wireIdentity, state.sender, state.receiver⟩

def Association.matches (a : Association) (p : PacketPolicy.Packet) : Bool :=
  decide (a.sourceLow ≤ p.source ∧ p.source ≤ a.sourceHigh ∧
    a.destinationLow ≤ p.destination ∧ p.destination ≤ a.destinationHigh)

def selectedAssociations (associations : List Association) (p : PacketPolicy.Packet) :
    List Association :=
  associations.filter fun a => a.matches p &&
    associations.all (fun b => !b.matches p || decide (a.priority ≤ b.priority))

inductive Action where
  | route | filter | encrypt | decrypt | wire | switch | local | deliver | drop
  deriving DecidableEq, Repr

structure Route where
  ingress : Nat
  egress : Nat
  low : Nat
  high : Nat
  prefixLength : Nat
  metric : Nat
  tablePriority : Nat
  deriving DecidableEq, Repr

def Route.matches (r : Route) (p : PacketPolicy.Packet) : Prop :=
  r.low ≤ p.destination ∧ p.destination ≤ r.high

def SelectedRoute (routes : List Route) (r : Route) (p : PacketPolicy.Packet) : Prop :=
  r ∈ routes ∧ r.matches p ∧ ∀ other ∈ routes, other.ingress = r.ingress →
    other.matches p → r.tablePriority ≤ other.tablePriority ∧
      (other.tablePriority = r.tablePriority → other.prefixLength ≤ r.prefixLength ∧
        (other.prefixLength = r.prefixLength → r.metric ≤ other.metric))

structure Config where
  routes : List Route
  forwardRules : Nat → List PacketPolicy.Rule
  inputRules : Nat → List PacketPolicy.Rule
  outputRules : Nat → List PacketPolicy.Rule
  forwardFallback : Nat → Filter.Verdict
  inputFallback : Nat → Filter.Verdict
  outputFallback : Nat → Filter.Verdict
  outbound : Nat → List Association
  inbound : Nat → List Association
  outboundStates : Nat → List SecurityAssociation
  inboundStates : Nat → List SecurityAssociation
  interfaceName : Nat → String
  owner : Nat → Nat
  link : Nat → Nat → Prop
  switching : Nat → Nat → PacketPolicy.Packet → Prop
  localAddress : Nat → Nat → Prop
  recipientDomain : Nat → Option Nat
  payloadOrigin : Nat → Prop

def policyPacket (c : Config) (port : Nat) (f : Frame) (authenticated : List Nat) :
    PacketPolicy.Packet :=
  { f.packet with
    egress := c.interfaceName port
    inboundPolicies := authenticated
    outboundPolicies := (selectedAssociations (c.outbound port) f.packet).map Association.id }

def accepts (rules : List PacketPolicy.Rule) (fallback : Filter.Verdict)
    (packet : PacketPolicy.Packet) : Prop :=
  Filter.evaluate (rules.map PacketPolicy.Rule.toFilter) fallback packet = .allow

def encrypt (a : Association) (sa : SecurityAssociation) (f : Frame) : Frame :=
  { f with
    packet := { f.packet with
      source := a.sender
      destination := a.receiver
      protocol := "esp"
      sourcePort := 0
      destinationPort := 0
      inboundPolicies := []
      outboundPolicies := []
      ipv4HeaderWords := InternetAddresses.headerWords a.sender
      ipv6NextHeader := if a.sender < 2^32 then 0 else 50 }
    envelopes := ⟨a.seal sa, f.packet⟩ :: f.envelopes }

inductive Step (c : Config) : State → Action → State → Prop
  | receive {port : Nat} {f : Frame} (tracking : String) :
      Step c ⟨port, .received, f, []⟩ .local
        ⟨port, .ingress, { f with enteredPort := port, packet := { f.packet with
          ingress := c.interfaceName port, inboundPolicies := [], outboundPolicies := [],
          connectionState := tracking } }, []⟩
  | route {port : Nat} {f : Frame} {authenticated : List Nat} (r : Route)
      (chosen : SelectedRoute c.routes r f.packet) (atIngress : r.ingress = port) :
      Step c ⟨port, .ingress, f, authenticated⟩ .route
        ⟨r.egress, .routed, f, authenticated⟩
  | outputRoute {port : Nat} {f : Frame} (r : Route)
      (chosen : SelectedRoute c.routes r f.packet) (atOrigin : r.ingress = port) :
      Step c ⟨port, .localOutput, f, []⟩ .route ⟨r.egress, .outputRouted, f, []⟩
  | filter {port : Nat} {f : Frame} {authenticated : List Nat}
      (accepted : accepts (c.forwardRules port) (c.forwardFallback port)
        (policyPacket c port f authenticated)) :
      Step c ⟨port, .routed, f, authenticated⟩ .filter
        ⟨port, .filtered, f, authenticated⟩
  | outputFilter {port : Nat} {f : Frame}
      (accepted : accepts (c.outputRules port) (c.outputFallback port)
        (policyPacket c port f [])) :
      Step c ⟨port, .outputRouted, f, []⟩ .filter ⟨port, .filtered, f, []⟩
  | encrypt {port : Nat} {f : Frame} {authenticated : List Nat} (a : Association)
      (sa : SecurityAssociation)
      (selected : a ∈ selectedAssociations (c.outbound port) f.packet)
      (installed : sa ∈ c.outboundStates port)
      (bound : StateBindsPolicy sa a) :
      Step c ⟨port, .filtered, f, authenticated⟩ .encrypt
        ⟨port, .encapsulated, encrypt a sa f, authenticated⟩
  | outerRoute {port : Nat} {f : Frame} {authenticated : List Nat} (r : Route)
      (chosen : SelectedRoute c.routes r f.packet) (atEncryptor : r.ingress = port) :
      Step c ⟨port, .encapsulated, f, authenticated⟩ .route
        ⟨r.egress, .ready, f, authenticated⟩
  | switch {a b : Nat} {f : Frame} {authenticated : List Nat}
      (permitted : c.switching a b f.packet) :
      Step c ⟨a, .ingress, f, authenticated⟩ .switch ⟨b, .ready, f, authenticated⟩
  | plain {port : Nat} {f : Frame} {authenticated : List Nat}
      (noPolicy : selectedAssociations (c.outbound port) f.packet = []) :
      Step c ⟨port, .filtered, f, authenticated⟩ .local
        ⟨port, .ready, f, authenticated⟩
  | decrypt {port : Nat} {f : Frame} (a : Association)
      (sa : SecurityAssociation) (header : PacketPolicy.Packet) (rest : List Envelope)
      (tracking : String)
      (configured : a ∈ c.inbound port)
      (installed : sa ∈ c.inboundStates port)
      (bound : StateBindsPolicy sa a)
      (received : f.envelopes = ⟨a.seal sa, header⟩ :: rest)
      (outerSource : f.packet.source = a.sender)
      (outerDestination : f.packet.destination = a.receiver)
      (esp : f.packet.protocol = "esp")
      (selected : a.matches header = true) :
      Step c ⟨port, .received, f, []⟩ .decrypt
        ⟨port, .ingress, { f with enteredPort := port, packet := { header with
          ingress := c.interfaceName port
          inboundPolicies := []
          outboundPolicies := [], connectionState := tracking }, envelopes := rest }, [a.id]⟩
  | wire {a b : Nat} {f : Frame} {authenticated : List Nat} (linked : c.link a b) :
      Step c ⟨a, .ready, f, authenticated⟩ .wire ⟨b, .received, f, []⟩
  | local {port : Nat} {f : Frame} {authenticated : List Nat}
      (addressed : c.localAddress port f.packet.destination)
      (accepted : accepts (c.inputRules port) (c.inputFallback port)
        (policyPacket c port f authenticated)) :
      Step c ⟨port, .ingress, f, authenticated⟩ .local
        ⟨port, .localInput, f, authenticated⟩
  | deliver {port : Nat} {f : Frame} {authenticated : List Nat} (domain : Nat)
      (recipient : c.recipientDomain port = some domain) (plaintext : f.envelopes = []) :
      Step c ⟨port, .localInput, f, authenticated⟩ .deliver
        ⟨port, .delivered, f, authenticated⟩
  | drop (s : State) :
      Step c s .drop { s with phase := .dropped }

def lts (c : Config) : Cslib.LTS State Action := ⟨Step c⟩

lemma step_preserves_payload {c : Config} {a b : State} {action : Action}
    (h : Step c a action b) :
    b.frame.payload = a.frame.payload ∧ b.frame.originDomain = a.frame.originDomain := by
  cases h <;> exact ⟨rfl, rfl⟩

lemma step_preserves_original_addresses {c : Config} {a b : State} {action : Action}
    (h : Step c a action b) : b.frame.addresses = a.frame.addresses := by
  cases h with
  | receive =>
    exact payload_addresses_ignore_metadata _ rfl rfl
  | decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    simp only [Frame.addresses, received, payloadAddresses]
    exact payload_addresses_ignore_metadata rest rfl rfl
  | encrypt => rfl
  | route => rfl
  | outputRoute => rfl
  | filter => rfl
  | outputFilter => rfl
  | outerRoute => rfl
  | switch => rfl
  | plain => rfl
  | wire => rfl
  | «local» => rfl
  | deliver => rfl
  | drop => rfl

theorem execution_preserves_original_addresses (c : Config) {a b : State}
    {actions : List Action} (execution : (lts c).MTr a actions b) :
    b.frame.addresses = a.frame.addresses := by
  have localProof : (lts c).TrInv (fun s => s.frame.addresses = a.frame.addresses) := by
    intro x action y step earlier
    exact (step_preserves_original_addresses step).trans earlier
  exact Cslib.LTS.mtrInv_of_trInv localProof a actions b execution rfl

theorem plaintext_delivery_retains_addresses (c : Config) {a b : State}
    {actions : List Action} (execution : (lts c).MTr a actions b)
    (initial : a.frame.envelopes = []) (delivered : b.frame.envelopes = []) :
    b.frame.packet.source = a.frame.packet.source ∧
    b.frame.packet.destination = a.frame.packet.destination := by
  have same := execution_preserves_original_addresses c execution
  simp only [Frame.addresses, initial, delivered, payloadAddresses, Prod.mk.injEq] at same
  exact same

theorem execution_preserves_payload (c : Config) {a b : State} {actions : List Action}
    (h : (lts c).MTr a actions b) :
    b.frame.payload = a.frame.payload ∧ b.frame.originDomain = a.frame.originDomain := by
  let invariant := fun s : State =>
    s.frame.payload = a.frame.payload ∧ s.frame.originDomain = a.frame.originDomain
  have localProof : (lts c).TrInv invariant := by
    intro x action y step before
    obtain ⟨hp, hd⟩ := step_preserves_payload step
    exact ⟨hp.trans before.1, hd.trans before.2⟩
  exact Cslib.LTS.mtrInv_of_trInv localProof a actions b h ⟨rfl, rfl⟩

lemma matched_policy_is_configured {associations : List Association} {p : PacketPolicy.Packet}
    {a : Association} (selected : a ∈ selectedAssociations associations p) :
    a ∈ associations ∧ a.matches p = true := by
  obtain ⟨member, matched⟩ := List.mem_filter.mp selected
  refine ⟨member, ?_⟩
  have both := Bool.and_eq_true_iff.mp matched
  exact both.1

theorem outbound_policy_atom_selects_operation (c : Config) (port : Nat) (f : Frame)
    (authenticated : List Nat) {rule : PacketPolicy.Rule} {id : Nat}
    (atom : .outboundPolicy id ∈ rule.atoms)
    (matched : rule.toFilter.accepts (policyPacket c port f authenticated) = true) :
    ∃ a ∈ c.outbound port, a.id = id ∧ a.matches f.packet = true := by
  have present : id ∈ (selectedAssociations (c.outbound port) f.packet).map Association.id :=
    PacketPolicy.matching_atom matched atom
  obtain ⟨a, selected, same⟩ := List.mem_map.mp present
  obtain ⟨installed, matched⟩ := matched_policy_is_configured selected
  exact ⟨a, installed, same, matched⟩

lemma outbound_policy_atom_excludes_plain (c : Config) (port : Nat) (f : Frame)
    (authenticated : List Nat) {rule : PacketPolicy.Rule} {id : Nat}
    (atom : .outboundPolicy id ∈ rule.atoms)
    (matched : rule.toFilter.accepts (policyPacket c port f authenticated) = true) :
    selectedAssociations (c.outbound port) f.packet ≠ [] := by
  have present : id ∈ (selectedAssociations (c.outbound port) f.packet).map Association.id :=
    PacketPolicy.matching_atom matched atom
  intro empty
  simp [empty] at present

lemma simulation_of_step_map {Abstract : Type} (c : Config)
    (abstractLTS : Cslib.LTS Abstract Action) (project : State → Abstract)
    (stepMap : ∀ a action b, Step c a action b →
      abstractLTS.Tr (project a) action (project b)) :
    Cslib.LTS.IsSimulation (lts c) abstractLTS (fun a b => project a = b) := by
  intro a b related action next step
  subst b
  exact ⟨project next, stepMap a action next step, rfl⟩

theorem matched_execution {Abstract : Type} (c : Config)
    (abstractLTS : Cslib.LTS Abstract Action) (project : State → Abstract)
    (stepMap : ∀ a action b, Step c a action b →
      abstractLTS.Tr (project a) action (project b))
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b) :
    abstractLTS.MTr (project a) actions (project b) := by
  obtain ⟨last, trace, related⟩ :=
    (simulation_of_step_map c abstractLTS project stepMap).sim_trace rfl actions b run
  simpa [← related] using trace

end TDN.Execution
