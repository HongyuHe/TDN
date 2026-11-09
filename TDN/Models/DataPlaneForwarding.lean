import Cslib.Foundations.Semantics.LTS.Simulation
import TDN.Models.IpsecAndAclRuleModel
import TDN.Models.UnifiedIpv4Ipv6AddressKey

namespace TDN.DataPlaneForwarding

structure TunnelSAStamp where
  tag : Nat
  association : Nat
  sender : Nat
  receiver : Nat
  deriving DecidableEq, Repr

structure EncapHeaderLayer where
  authentication : TunnelSAStamp
  header : PacketPolicy.Packet

structure Frame where
  payload : Nat
  originDomain : Nat
  packet : PacketPolicy.Packet
  encapLayers : List EncapHeaderLayer
  enteredIface : Nat := 0

def payloadAddresses (packet : PacketPolicy.Packet) : List EncapHeaderLayer → Nat × Nat
  | [] => (packet.source, packet.destination)
  | envelope :: rest => payloadAddresses envelope.header rest

def Frame.addresses (frame : Frame) : Nat × Nat :=
  payloadAddresses frame.packet frame.encapLayers

lemma payload_addresses_ignore_metadata {a b : PacketPolicy.Packet} (encapLayers : List EncapHeaderLayer)
    (source : a.source = b.source) (destination : a.destination = b.destination) :
    payloadAddresses a encapLayers = payloadAddresses b encapLayers := by
  cases encapLayers with
  | nil => exact Prod.ext source destination
  | cons => rfl

inductive DatapathStage where
  | received | ingress | localOutput | routed | outputRouted
  | filtered | encapsulated | egressReady | localInput | delivered | dropped
  deriving DecidableEq, Repr

structure State where
  iface : Nat
  datapathStage : DatapathStage
  frame : Frame
  authenticated : List Nat

structure IpsecPolicy where
  id : Nat
  tag : Nat
  sender : Nat
  receiver : Nat
  sourceLow : Nat
  sourceHigh : Nat
  destinationLow : Nat
  destinationHigh : Nat
  priority : Nat
  requiredSpi : Option Nat := none
  deriving DecidableEq, Repr

structure InstalledSA where
  reqid : Nat
  spi : Nat
  sender : Nat
  receiver : Nat
  deriving DecidableEq, Repr

def saMatchesPolicy (state : InstalledSA) (policy : IpsecPolicy) : Prop :=
  state.reqid = policy.id ∧ state.sender = policy.sender ∧
  state.receiver = policy.receiver ∧
  (policy.requiredSpi = none ∨ policy.requiredSpi = some state.spi)

def IpsecPolicy.seal (a : IpsecPolicy) (state : InstalledSA) : TunnelSAStamp :=
  ⟨a.tag, state.spi, state.sender, state.receiver⟩

def IpsecPolicy.matches (a : IpsecPolicy) (p : PacketPolicy.Packet) : Bool :=
  decide (a.sourceLow ≤ p.source ∧ p.source ≤ a.sourceHigh ∧
    a.destinationLow ≤ p.destination ∧ p.destination ≤ a.destinationHigh)

def lookupSpdPolicies (associations : List IpsecPolicy) (p : PacketPolicy.Packet) :
    List IpsecPolicy :=
  associations.filter fun a => a.matches p &&
    associations.all (fun b => !b.matches p || decide (a.priority ≤ b.priority))

inductive Action where
  | route | filter | encrypt | decrypt | linkTransmit | bridge | internalProcessing | deliver | drop
  deriving DecidableEq, Repr

structure FibRoute where
  ingress : Nat
  egress : Nat
  destPrefixLow : Nat
  destPrefixHigh : Nat
  prefixLength : Nat
  metric : Nat
  tablePriority : Nat
  deriving DecidableEq, Repr

def FibRoute.matches (r : FibRoute) (p : PacketPolicy.Packet) : Prop :=
  r.destPrefixLow ≤ p.destination ∧ p.destination ≤ r.destPrefixHigh

def SelectedFibRoute (routes : List FibRoute) (r : FibRoute) (p : PacketPolicy.Packet) : Prop :=
  r ∈ routes ∧ r.matches p ∧ ∀ other ∈ routes, other.ingress = r.ingress →
    other.matches p → r.tablePriority ≤ other.tablePriority ∧
      (other.tablePriority = r.tablePriority → other.prefixLength ≤ r.prefixLength ∧
        (other.prefixLength = r.prefixLength → r.metric ≤ other.metric))

structure DataPlaneModel where
  routes : List FibRoute
  forwardRules : Nat → List PacketPolicy.Rule
  inputRules : Nat → List PacketPolicy.Rule
  outputRules : Nat → List PacketPolicy.Rule
  forwardFallback : Nat → Filter.Verdict
  inputFallback : Nat → Filter.Verdict
  outputFallback : Nat → Filter.Verdict
  egressPolicies : Nat → List IpsecPolicy
  ingressPolicies : Nat → List IpsecPolicy
  egressSAs : Nat → List InstalledSA
  ingressSAs : Nat → List InstalledSA
  interfaceName : Nat → String
  owner : Nat → Nat
  link : Nat → Nat → Prop
  bridging : Nat → Nat → PacketPolicy.Packet → Prop
  localAddress : Nat → Nat → Prop
  ifaceSecurityDomain : Nat → Option Nat
  canOriginateTraffic : Nat → Prop

def policyPacket (c : DataPlaneModel) (iface : Nat) (f : Frame) (authenticated : List Nat) :
    PacketPolicy.Packet :=
  { f.packet with
    egress := c.interfaceName iface
    matchedInboundPolicyIds := authenticated
    matchedOutboundPolicyIds := (lookupSpdPolicies (c.egressPolicies iface) f.packet).map IpsecPolicy.id }

def accepts (rules : List PacketPolicy.Rule) (fallback : Filter.Verdict)
    (packet : PacketPolicy.Packet) : Prop :=
  Filter.evaluate (rules.map PacketPolicy.Rule.toFilter) fallback packet = .allow

def encrypt (a : IpsecPolicy) (sa : InstalledSA) (f : Frame) : Frame :=
  { f with
    packet := { f.packet with
      source := a.sender
      destination := a.receiver
      protocol := "esp"
      sourcePort := 0
      destinationPort := 0
      matchedInboundPolicyIds := []
      matchedOutboundPolicyIds := []
      ipv4HeaderWords := InternetAddresses.headerWords a.sender
      ipv6NextHeader := if a.sender < 2^32 then 0 else 50 }
    encapLayers := ⟨a.seal sa, f.packet⟩ :: f.encapLayers }

inductive Step (c : DataPlaneModel) : State → Action → State → Prop
  | receive {iface : Nat} {f : Frame} (tracking : String) :
      Step c ⟨iface, .received, f, []⟩ .internalProcessing
        ⟨iface, .ingress, { f with enteredIface := iface, packet := { f.packet with
          ingress := c.interfaceName iface, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [],
          connectionState := tracking } }, []⟩
  | route {iface : Nat} {f : Frame} {authenticated : List Nat} (r : FibRoute)
      (chosen : SelectedFibRoute c.routes r f.packet) (atIngress : r.ingress = iface) :
      Step c ⟨iface, .ingress, f, authenticated⟩ .route
        ⟨r.egress, .routed, f, authenticated⟩
  | routeLocalOutput {iface : Nat} {f : Frame} (r : FibRoute)
      (chosen : SelectedFibRoute c.routes r f.packet) (atOrigin : r.ingress = iface) :
      Step c ⟨iface, .localOutput, f, []⟩ .route ⟨r.egress, .outputRouted, f, []⟩
  | filter {iface : Nat} {f : Frame} {authenticated : List Nat}
      (accepted : accepts (c.forwardRules iface) (c.forwardFallback iface)
        (policyPacket c iface f authenticated)) :
      Step c ⟨iface, .routed, f, authenticated⟩ .filter
        ⟨iface, .filtered, f, authenticated⟩
  | outputFilter {iface : Nat} {f : Frame}
      (accepted : accepts (c.outputRules iface) (c.outputFallback iface)
        (policyPacket c iface f [])) :
      Step c ⟨iface, .outputRouted, f, []⟩ .filter ⟨iface, .filtered, f, []⟩
  | encrypt {iface : Nat} {f : Frame} {authenticated : List Nat} (a : IpsecPolicy)
      (sa : InstalledSA)
      (selected : a ∈ lookupSpdPolicies (c.egressPolicies iface) f.packet)
      (installed : sa ∈ c.egressSAs iface)
      (bound : saMatchesPolicy sa a) :
      Step c ⟨iface, .filtered, f, authenticated⟩ .encrypt
        ⟨iface, .encapsulated, encrypt a sa f, authenticated⟩
  | routeOuterPacket {iface : Nat} {f : Frame} {authenticated : List Nat} (r : FibRoute)
      (chosen : SelectedFibRoute c.routes r f.packet) (atEncryptor : r.ingress = iface) :
      Step c ⟨iface, .encapsulated, f, authenticated⟩ .route
        ⟨r.egress, .egressReady, f, authenticated⟩
  | bridge {a b : Nat} {f : Frame} {authenticated : List Nat}
      (permitted : c.bridging a b f.packet) :
      Step c ⟨a, .ingress, f, authenticated⟩ .bridge ⟨b, .egressReady, f, authenticated⟩
  | forwardWithoutEncap {iface : Nat} {f : Frame} {authenticated : List Nat}
      (noPolicy : lookupSpdPolicies (c.egressPolicies iface) f.packet = []) :
      Step c ⟨iface, .filtered, f, authenticated⟩ .internalProcessing
        ⟨iface, .egressReady, f, authenticated⟩
  | decrypt {iface : Nat} {f : Frame} (a : IpsecPolicy)
      (sa : InstalledSA) (header : PacketPolicy.Packet) (rest : List EncapHeaderLayer)
      (tracking : String)
      (configured : a ∈ c.ingressPolicies iface)
      (installed : sa ∈ c.ingressSAs iface)
      (bound : saMatchesPolicy sa a)
      (received : f.encapLayers = ⟨a.seal sa, header⟩ :: rest)
      (outerSource : f.packet.source = a.sender)
      (outerDestination : f.packet.destination = a.receiver)
      (esp : f.packet.protocol = "esp")
      (selected : a.matches header = true) :
      Step c ⟨iface, .received, f, []⟩ .decrypt
        ⟨iface, .ingress, { f with enteredIface := iface, packet := { header with
          ingress := c.interfaceName iface
          matchedInboundPolicyIds := []
          matchedOutboundPolicyIds := [], connectionState := tracking }, encapLayers := rest }, [a.id]⟩
  | linkTransmit {a b : Nat} {f : Frame} {authenticated : List Nat} (linked : c.link a b) :
      Step c ⟨a, .egressReady, f, authenticated⟩ .linkTransmit ⟨b, .received, f, []⟩
  | deliverToLocalHost {iface : Nat} {f : Frame} {authenticated : List Nat}
      (addressed : c.localAddress iface f.packet.destination)
      (accepted : accepts (c.inputRules iface) (c.inputFallback iface)
        (policyPacket c iface f authenticated)) :
      Step c ⟨iface, .ingress, f, authenticated⟩ .internalProcessing
        ⟨iface, .localInput, f, authenticated⟩
  | deliver {iface : Nat} {f : Frame} {authenticated : List Nat} (domain : Nat)
      (recipient : c.ifaceSecurityDomain iface = some domain) (plaintext : f.encapLayers = []) :
      Step c ⟨iface, .localInput, f, authenticated⟩ .deliver
        ⟨iface, .delivered, f, authenticated⟩
  | drop (s : State) :
      Step c s .drop { s with datapathStage := .dropped }

def lts (c : DataPlaneModel) : Cslib.LTS State Action := ⟨Step c⟩

def ForwardsAlongTrace (net : DataPlaneModel) (startPkt : State)
    (actions : List Action) (endPkt : State) : Prop :=
  (lts net).MTr startPkt actions endPkt

lemma step_preserves_payload {c : DataPlaneModel} {a b : State} {action : Action}
    (h : Step c a action b) :
    b.frame.payload = a.frame.payload ∧ b.frame.originDomain = a.frame.originDomain := by
  cases h <;> exact ⟨rfl, rfl⟩

lemma step_preserves_original_addresses {c : DataPlaneModel} {a b : State} {action : Action}
    (h : Step c a action b) : b.frame.addresses = a.frame.addresses := by
  cases h with
  | receive =>
    exact payload_addresses_ignore_metadata _ rfl rfl
  | decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    simp only [Frame.addresses, received, payloadAddresses]
    exact payload_addresses_ignore_metadata rest rfl rfl
  | encrypt => rfl
  | route => rfl
  | routeLocalOutput => rfl
  | filter => rfl
  | outputFilter => rfl
  | routeOuterPacket => rfl
  | bridge => rfl
  | forwardWithoutEncap => rfl
  | linkTransmit => rfl
  | deliverToLocalHost => rfl
  | deliver => rfl
  | drop => rfl

theorem forwarding_preserves_original_addresses (c : DataPlaneModel) {a b : State}
    {actions : List Action} (execution : (lts c).MTr a actions b) :
    b.frame.addresses = a.frame.addresses := by
  have localProof : (lts c).TrInv (fun s => s.frame.addresses = a.frame.addresses) := by
    intro x action y step earlier
    exact (step_preserves_original_addresses step).trans earlier
  exact Cslib.LTS.mtrInv_of_trInv localProof a actions b execution rfl

theorem plaintext_delivery_retains_addresses (c : DataPlaneModel) {a b : State}
    {actions : List Action} (execution : (lts c).MTr a actions b)
    (initial : a.frame.encapLayers = []) (delivered : b.frame.encapLayers = []) :
    b.frame.packet.source = a.frame.packet.source ∧
    b.frame.packet.destination = a.frame.packet.destination := by
  have same := forwarding_preserves_original_addresses c execution
  simp only [Frame.addresses, initial, delivered, payloadAddresses, Prod.mk.injEq] at same
  exact same

theorem forwarding_preserves_payload (c : DataPlaneModel) {a b : State} {actions : List Action}
    (h : (lts c).MTr a actions b) :
    b.frame.payload = a.frame.payload ∧ b.frame.originDomain = a.frame.originDomain := by
  let invariant := fun s : State =>
    s.frame.payload = a.frame.payload ∧ s.frame.originDomain = a.frame.originDomain
  have localProof : (lts c).TrInv invariant := by
    intro x action y step before
    obtain ⟨hp, hd⟩ := step_preserves_payload step
    exact ⟨hp.trans before.1, hd.trans before.2⟩
  exact Cslib.LTS.mtrInv_of_trInv localProof a actions b h ⟨rfl, rfl⟩

lemma matched_policy_is_configured {associations : List IpsecPolicy} {p : PacketPolicy.Packet}
    {a : IpsecPolicy} (selected : a ∈ lookupSpdPolicies associations p) :
    a ∈ associations ∧ a.matches p = true := by
  obtain ⟨member, matched⟩ := List.mem_filter.mp selected
  refine ⟨member, ?_⟩
  have both := Bool.and_eq_true_iff.mp matched
  exact both.1

theorem outbound_policy_atom_selects_operation (c : DataPlaneModel) (iface : Nat) (f : Frame)
    (authenticated : List Nat) {rule : PacketPolicy.Rule} {id : Nat}
    (atom : .outboundPolicy id ∈ rule.atoms)
    (matched : rule.toFilter.accepts (policyPacket c iface f authenticated) = true) :
    ∃ a ∈ c.egressPolicies iface, a.id = id ∧ a.matches f.packet = true := by
  have present : id ∈ (lookupSpdPolicies (c.egressPolicies iface) f.packet).map IpsecPolicy.id :=
    PacketPolicy.matching_atom matched atom
  obtain ⟨a, selected, same⟩ := List.mem_map.mp present
  obtain ⟨installed, matched⟩ := matched_policy_is_configured selected
  exact ⟨a, installed, same, matched⟩

lemma outbound_policy_atom_excludes_plain (c : DataPlaneModel) (iface : Nat) (f : Frame)
    (authenticated : List Nat) {rule : PacketPolicy.Rule} {id : Nat}
    (atom : .outboundPolicy id ∈ rule.atoms)
    (matched : rule.toFilter.accepts (policyPacket c iface f authenticated) = true) :
    lookupSpdPolicies (c.egressPolicies iface) f.packet ≠ [] := by
  have present : id ∈ (lookupSpdPolicies (c.egressPolicies iface) f.packet).map IpsecPolicy.id :=
    PacketPolicy.matching_atom matched atom
  intro empty
  simp [empty] at present

lemma simulation_of_step_map {Abstract : Type} (c : DataPlaneModel)
    (abstractLTS : Cslib.LTS Abstract Action) (project : State → Abstract)
    (stepMap : ∀ a action b, Step c a action b →
      abstractLTS.Tr (project a) action (project b)) :
    Cslib.LTS.IsSimulation (lts c) abstractLTS (fun a b => project a = b) := by
  intro a b related action next step
  subst b
  exact ⟨project next, stepMap a action next step, rfl⟩

theorem matched_forwarding {Abstract : Type} (c : DataPlaneModel)
    (abstractLTS : Cslib.LTS Abstract Action) (project : State → Abstract)
    (stepMap : ∀ a action b, Step c a action b →
      abstractLTS.Tr (project a) action (project b))
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b) :
    abstractLTS.MTr (project a) actions (project b) := by
  obtain ⟨last, trace, related⟩ :=
    (simulation_of_step_map c abstractLTS project stepMap).sim_trace rfl actions b run
  simpa [← related] using trace

end TDN.DataPlaneForwarding
