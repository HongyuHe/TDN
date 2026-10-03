import TDN.Network.Packet
import TDN.Network.Routing
import TDN.Network.Graph

/-!
The execution vocabulary separates wire transfer, Ethernet switching, and an
IP-forwarding operation. Forwarding uses sampled routes and routing rules,
inbound XFRM validation, the actual filter callback, and outbound XFRM policy/SA
selection. Device names and filter implementations are parameters. The selected
profile covers complete IPv4 datagrams; fragmentation and time-varying state
need extensions before the model can describe those behaviors.
-/
namespace TDN.Network.Execution

structure Endpoint (Node : Type) where
  node : Node
  port : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Model (Node : Type) where
  observed : Node → Option OperationalSnapshot
  retainedPorts : Node → List String
  inputFilter : Node → String → IPv4Header → Bool
  forwardFilter : Node → String → String → IPv4Header → Option Nat → Option Nat → Bool
  outputFilter : Node → String → IPv4Header → Bool
  linked : Endpoint Node → Endpoint Node → Prop
  bridge : Endpoint Node → Endpoint Node → Prop
  protectionFloor : Endpoint Node → Nat

variable {Node Message : Type}

def Model.interfaces (model : Model Node) (node : Node) : List ObservedInterface :=
  ((model.observed node).bind OperationalSnapshot.interfaces).getD []

def Model.policies (model : Model Node) (node : Node) : List XfrmPolicy :=
  ((model.observed node).bind OperationalSnapshot.policies).getD []

def Model.states (model : Model Node) (node : Node) : List XfrmState :=
  ((model.observed node).bind OperationalSnapshot.states).getD []

def Model.route (model : Model Node) (node : Node) (header : IPv4Header) : Option FibRoute := do
  let observed ← model.observed node
  let routes ← observed.routes
  let rules ← observed.routingRules
  Routing.lookup routes rules header.source header.destination

def Model.livePort (model : Model Node) (node : Node) (port : String) (bytes : Nat) : Bool :=
  (model.retainedPorts node).contains port &&
    (model.interfaces node).any fun interface =>
      interface.name == port && interface.up && interface.carrier && bytes ≤ interface.mtu

def selectorMatches (policy : XfrmPolicy) (header : IPv4Header) : Bool :=
  policy.source.contains header.source && policy.destination.contains header.destination

def Model.policy (model : Model Node) (node : Node) (direction : String)
    (header : IPv4Header) : Option XfrmPolicy :=
  Routing.select (fun a b => a.priority < b.priority)
    ((model.policies node).filter fun policy => policy.direction == direction && selectorMatches policy header)

def stateMatches (policy : XfrmPolicy) (state : XfrmState) : Bool :=
  state.reqid == policy.reqid && state.source == policy.tunnelSource &&
    state.destination == policy.tunnelDestination && state.mode == policy.mode &&
    state.protocol == policy.protocol && state.mode == "tunnel" && state.protocol == "esp" &&
    state.algorithm == "rfc4106(gcm(aes))" && state.integrityBits == 128 && state.tfcPadding == 0 &&
    (policy.spi == 0 || policy.spi == state.spi) && (state.flags == 0 || state.flags == 32)

/-- A nonzero observed template SPI cannot select a different SA, even when
its endpoint pair and request ID match. Zero preserves the kernel wildcard. -/
theorem state_match_respects_template_spi (policy : XfrmPolicy) (state : XfrmState)
    (matched : stateMatches policy state = true) : policy.spi = 0 ∨ policy.spi = state.spi := by
  simp_all [stateMatches]

/-- Missing required outbound SA returns `none`. An absent outbound policy
returns an unchanged packet; the forwarding filter must reject any unsafe
plaintext fallback. The model therefore does not build fail-closed behavior
into the result type or assume that every gateway always encrypts. -/
def Model.send (model : Model Node) (node : Node) (packet : WirePacket Message) :
    Option (WirePacket Message × Option Nat) := do
  match model.policy node "out" packet.header with
  | none => some (packet, none)
  | some policy =>
    let state ← (model.states node).find? (stateMatches policy)
    some (packet.seal state, some policy.reqid)

/-- A transit cipher stays intact. A cipher addressed locally must satisfy
local INPUT filtering and the sampled inbound and forwarding XFRM templates.
Matching the wire identity represents trusted authenticated decryption. The
receiver policy and SA use the receiver-local request ID; the sender request
ID remains provenance metadata and does not constrain inbound SA lookup. -/
def Model.receive (model : Model Node) (node : Node) (port : String)
    (packet : WirePacket Message) : Option (WirePacket Message × Option Nat) := do
  match packet with
  | .clear _ _ => some (packet, none)
  | .cipher header identity body =>
    let outerRoute ← model.route node header
    if outerRoute.kind != "local" then some (packet, none) else
    if !model.inputFilter node port header then none else
    let policy ← model.policy node "in" body.header
    let forward ← model.policy node "fwd" body.header
    if policy.reqid != forward.reqid then none else
    let state ← (model.states node).find? fun state =>
      stateMatches policy state && ESPWireIdentity.ofState state == identity.wire
    if !(stateMatches forward state) then none else
    some (body, some state.reqid)

structure ForwardResult (Message : Type) where
  body : WirePacket Message
  packet : WirePacket Message
  route : FibRoute
  inputTag : Option Nat
  outputTag : Option Nat
  deriving DecidableEq, BEq, Repr

/-- Rejected local INPUT prevents decapsulation of the arriving packet.
Successful receive can therefore only leave the complete packet unchanged. -/
theorem receive_with_denied_input_preserves (model : Model Node) (node : Node)
    (port : String) (packet body : WirePacket Message) (tag : Option Nat)
    (denied : model.inputFilter node port packet.header = false)
    (received : model.receive node port packet = some (body, tag)) :
    body = packet ∧ tag = none := by
  cases packet with
  | clear header message => simpa [Model.receive, eq_comm] using received
  | cipher header identity inner =>
    change model.inputFilter node port header = false at denied
    cases routed : model.route node header with
    | none => simp [Model.receive, routed] at received
    | some route =>
      simp only [Model.receive, routed, bind, Option.bind_some] at received
      split at received
      · simpa [eq_comm] using received
      · simp [denied] at received

/-- A port with no accepted local INPUT packet cannot decapsulate a locally
addressed cipher. Any successful receive therefore preserves the whole wire
packet. Transit ciphertext and clear packets remain ordinary possibilities. -/
theorem receive_without_local_input_preserves (model : Model Node) (node : Node) (port : String)
    (denied : ∀ header, model.inputFilter node port header = false)
    (packet body : WirePacket Message) (tag : Option Nat)
    (received : model.receive node port packet = some (body, tag)) :
    body = packet ∧ tag = none :=
  receive_with_denied_input_preserves model node port packet body tag (denied packet.header) received

def Model.forward (model : Model Node) (node : Node) (input : String)
    (packet : WirePacket Message) : Option (ForwardResult Message) := do
  if ((model.observed node).bind OperationalSnapshot.forwarding) != some true then none else
  if !model.livePort node input packet.header.bytes then none else
  let (body, inputTag) ← model.receive node input packet
  let route ← model.route node body.header
  if route.kind != "unicast" then none else
  let (sent, outputTag) ← model.send node body
  let wireRoute ← model.route node sent.header
  if wireRoute.kind != "unicast" then none else
  if !model.forwardFilter node input wireRoute.output body.header inputTag outputTag then none else
  if !model.livePort node wireRoute.output sent.header.bytes then none else
  some ⟨body, sent, wireRoute, inputTag, outputTag⟩

/-- Local delivery is a separate terminal check after possible decryption.
It requires a local FIB result and the device's INPUT policy. -/
def Model.deliver (model : Model Node) (node : Node) (input : String)
    (packet : WirePacket Message) : Option (WirePacket Message) := do
  if !model.livePort node input packet.header.bytes then none else
  let (body, _) ← model.receive node input packet
  let route ← model.route node body.header
  if route.kind != "local" || !model.inputFilter node input body.header then none else
  some body

def tagCost (tag : Option Nat) : Nat := if tag.isSome then 1 else 0

def Model.tags (model : Model Node) (node : Node) : List (Option Nat) :=
  none :: ((model.policies node).map (fun p => some p.reqid) ++
    (model.states node).map (fun s => some s.reqid))

theorem selected_policy_is_observed (model : Model Node) (node : Node)
    (direction : String) (header : IPv4Header) (policy : XfrmPolicy)
    (selected : model.policy node direction header = some policy) : policy ∈ model.policies node := by
  have member := Routing.selected_is_member _ _ policy selected
  exact (List.mem_filter.mp member).1

/-- An endpoint with an observed empty XFRM policy list cannot deliver an
encrypted packet through this IPv4/IPsec delivery operation. A transit cipher
keeps a nonlocal route; a local cipher needs an inbound policy. -/
theorem delivery_without_xfrm_is_clear (model : Model Node) (node : Node) (port : String)
    (packet result : WirePacket Message) (empty : model.policies node = [])
    (delivered : model.deliver node port packet = some result) :
    packet.depth = 0 ∧ result = packet := by
  have absent (direction : String) (header : IPv4Header) :
      model.policy node direction header = none := by
    simp [Model.policy, empty, Routing.select]
  cases packet with
  | clear header message =>
    simp only [Model.deliver] at delivered
    split at delivered
    next => simp at delivered
    next =>
      simp only [Model.receive, bind, Option.bind_some, Option.bind_eq_some_iff] at delivered
      obtain ⟨route, _, accepted⟩ := delivered
      split at accepted
      next => simp at accepted
      next =>
        simp only [Option.some.injEq] at accepted
        exact ⟨rfl, accepted.symm⟩
  | cipher header identity body =>
    simp only [Model.deliver] at delivered
    split at delivered
    next => simp at delivered
    next =>
      cases route : model.route node header with
      | none => simp [Model.receive, route] at delivered
      | some outerRoute =>
        by_cases localRoute : outerRoute.kind = "local"
        · simp [Model.receive, route, localRoute, absent] at delivered
        · simp [Model.receive, route, localRoute, WirePacket.header] at delivered

theorem send_layer_accounting (model : Model Node) (node : Node)
    (packet sent : WirePacket Message) (tag : Option Nat)
    (accepted : model.send node packet = some (sent, tag)) :
    sent.message = packet.message ∧ sent.depth = packet.depth + tagCost tag ∧ tag ∈ model.tags node := by
  cases selected : model.policy node "out" packet.header with
  | none =>
    simp [Model.send, selected] at accepted
    obtain ⟨rfl, rfl⟩ := accepted
    simp [tagCost, Model.tags]
  | some policy =>
    cases state : (model.states node).find? (stateMatches policy) with
    | none => simp [Model.send, selected, state] at accepted
    | some sa =>
      simp [Model.send, selected, state] at accepted
      obtain ⟨rfl, rfl⟩ := accepted
      have member := selected_policy_is_observed model node "out" packet.header policy selected
      simp only [seal_preserves_message, seal_adds_one_layer, tagCost, Option.isSome_some,
        ↓reduceIte, true_and]
      simp only [Model.tags, List.mem_cons, List.mem_append, List.mem_map]
      exact Or.inr (Or.inl ⟨policy, member, rfl⟩)

theorem receive_layer_accounting (model : Model Node) (node : Node) (port : String)
    (packet body : WirePacket Message) (tag : Option Nat)
    (accepted : model.receive node port packet = some (body, tag)) :
    packet.message = body.message ∧ packet.depth = body.depth + tagCost tag ∧
      tag ∈ model.tags node ∧
      (tag.isSome = true → model.inputFilter node port packet.header = true) := by
  cases packet with
  | clear header message =>
    simp [Model.receive] at accepted
    obtain ⟨rfl, rfl⟩ := accepted
    simp [tagCost, Model.tags]
  | cipher header identity inner =>
    unfold Model.receive at accepted
    cases outer : model.route node header with
    | none => simp [outer] at accepted
    | some route =>
      by_cases localRoute : route.kind = "local"
      · by_cases filter : model.inputFilter node port header = true
        · simp [outer, localRoute, filter, Option.bind_eq_some_iff] at accepted
          obtain ⟨policy, _, forward, _, same, state, selected, matched, equal⟩ := accepted
          obtain ⟨rfl, rfl⟩ := equal
          have member := List.mem_of_find?_eq_some selected
          refine ⟨rfl, ?_, ?_, ?_⟩
          · simp [WirePacket.depth, tagCost]
          · simp only [Model.tags, List.mem_cons, List.mem_append, List.mem_map]
            exact Or.inr (Or.inr ⟨state, member, rfl⟩)
          · simpa [WirePacket.header] using filter
        · simp [outer, localRoute, filter] at accepted
      · simp [outer, localRoute] at accepted
        obtain ⟨rfl, rfl⟩ := accepted
        simp [tagCost, Model.tags]

theorem send_preserves_original_header (model : Model Node) (node : Node)
    (packet sent : WirePacket Message) (tag : Option Nat)
    (accepted : model.send node packet = some (sent, tag)) :
    sent.originalHeader = packet.originalHeader := by
  cases selected : model.policy node "out" packet.header with
  | none =>
    simp [Model.send, selected] at accepted
    obtain ⟨rfl, rfl⟩ := accepted
    rfl
  | some policy =>
    cases state : (model.states node).find? (stateMatches policy) with
    | none => simp [Model.send, selected, state] at accepted
    | some sa =>
      simp [Model.send, selected, state] at accepted
      obtain ⟨rfl, rfl⟩ := accepted
      rfl

theorem receive_preserves_original_header (model : Model Node) (node : Node) (port : String)
    (packet body : WirePacket Message) (tag : Option Nat)
    (accepted : model.receive node port packet = some (body, tag)) :
    packet.originalHeader = body.originalHeader := by
  cases packet with
  | clear header message =>
    simp [Model.receive] at accepted
    obtain ⟨rfl, rfl⟩ := accepted
    rfl
  | cipher header identity inner =>
    unfold Model.receive at accepted
    cases outer : model.route node header with
    | none => simp [outer] at accepted
    | some route =>
      by_cases localRoute : route.kind = "local"
      · by_cases filter : model.inputFilter node port header = true
        · simp [outer, localRoute, filter, Option.bind_eq_some_iff] at accepted
          obtain ⟨_, _, _, _, _, _, _, _, equal⟩ := accepted
          obtain ⟨rfl, rfl⟩ := equal
          rfl
        · simp [outer, localRoute, filter] at accepted
      · simp [outer, localRoute] at accepted
        obtain ⟨rfl, rfl⟩ := accepted
        rfl

theorem forward_evidence (model : Model Node) (node : Node) (input : String)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result) :
    model.receive node input packet = some (result.body, result.inputTag) ∧
    model.send node result.body = some (result.packet, result.outputTag) ∧
    model.forwardFilter node input result.route.output result.body.header result.inputTag result.outputTag = true ∧
    model.livePort node input packet.header.bytes = true ∧
    model.livePort node result.route.output result.packet.header.bytes = true := by
  unfold Model.forward at accepted
  split at accepted
  · simp at accepted
  · split at accepted
    · simp at accepted
    · simp only [bind, Option.bind_eq_some_iff] at accepted
      obtain ⟨⟨body, inputTag⟩, received, rest⟩ := accepted
      obtain ⟨route, routed, rest⟩ := rest
      split at rest
      · simp at rest
      · simp only [Option.bind_eq_some_iff] at rest
        obtain ⟨⟨sent, outputTag⟩, sentProof, rest⟩ := rest
        obtain ⟨wireRoute, wireRouted, rest⟩ := rest
        split at rest
        · simp at rest
        · split at rest
          · simp at rest
          · split at rest
            · simp at rest
            · simp only [Option.some.injEq] at rest
              subst result
              simp_all

theorem clear_forward_filter_uses_original_header (model : Model Node) (node : Node)
    (input : String) (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result) (clear : result.packet.depth = 0) :
    model.forwardFilter node input result.route.output result.packet.originalHeader result.inputTag result.outputTag = true := by
  obtain ⟨_, sent, filtered, _, _⟩ := forward_evidence model node input packet result accepted
  have size := (send_layer_accounting model node result.body result.packet result.outputTag sent).2.1
  have bodyClear : result.body.depth = 0 := by omega
  have preserved := send_preserves_original_header model node result.body result.packet result.outputTag sent
  rw [zero_depth_header_is_original result.body bodyClear, ← preserved] at filtered
  exact filtered

inductive Phase where
  | input | output
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure State (Node Message : Type) where
  location : Endpoint Node
  phase : Phase
  packet : WirePacket Message
  deriving DecidableEq, BEq, Repr

inductive Step (model : Model Node) : State Node Message → State Node Message → Prop where
  | wire (a b : Endpoint Node) (packet : WirePacket Message)
      (link : model.linked a b)
      (upA : model.livePort a.node a.port packet.header.bytes = true)
      (upB : model.livePort b.node b.port packet.header.bytes = true) :
      Step model ⟨a, .output, packet⟩ ⟨b, .input, packet⟩
  | switch (a b : Endpoint Node) (packet : WirePacket Message)
      (connection : model.bridge a b)
      (upA : model.livePort a.node a.port packet.header.bytes = true)
      (upB : model.livePort b.node b.port packet.header.bytes = true) :
      Step model ⟨a, .input, packet⟩ ⟨b, .output, packet⟩
  | forward (node : Node) (input : String) (packet : WirePacket Message)
      (result : ForwardResult Message) (accepted : model.forward node input packet = some result) :
      Step model ⟨⟨node, input⟩, .input, packet⟩
        ⟨⟨node, result.route.output⟩, .output, result.packet⟩

def Protected (model : Model Node) (state : State Node Message) : Prop :=
  state.packet.message.isSome = true → model.protectionFloor state.location ≤ state.packet.depth

theorem step_preserves_message (model : Model Node) {before after : State Node Message}
    (step : Step model before after) : before.packet.message = after.packet.message := by
  cases step with
  | wire => rfl
  | switch => rfl
  | forward node input packet result accepted =>
    obtain ⟨received, sent, _, _, _⟩ := forward_evidence model node input packet result accepted
    have inputMessage := (receive_layer_accounting model node input packet result.body result.inputTag received).1
    have outputMessage := (send_layer_accounting model node result.body result.packet result.outputTag sent).1
    exact inputMessage.trans outputMessage.symm

theorem execution_preserves_message (model : Model Node) {before after : State Node Message}
    (path : Reach (Step model) before after) : before.packet.message = after.packet.message :=
  path.preserves (fun state => state.packet.message) (fun _ _ edge => step_preserves_message model edge)

theorem step_preserves_original_header (model : Model Node) {before after : State Node Message}
    (step : Step model before after) : before.packet.originalHeader = after.packet.originalHeader := by
  cases step with
  | wire => rfl
  | switch => rfl
  | forward node input packet result accepted =>
    obtain ⟨received, sent, _, _, _⟩ := forward_evidence model node input packet result accepted
    have incoming := receive_preserves_original_header model node input packet result.body result.inputTag received
    have outgoing := send_preserves_original_header model node result.body result.packet result.outputTag sent
    exact incoming.trans outgoing.symm

theorem execution_preserves_original_header (model : Model Node) {before after : State Node Message}
    (path : Reach (Step model) before after) : before.packet.originalHeader = after.packet.originalHeader :=
  path.preserves (fun state => state.packet.originalHeader) (fun _ _ edge => step_preserves_original_header model edge)

/-- A local budget is a condition on interfaces, filter decisions, and possible
XFRM tags. It can be checked once on finite rule signatures. The condition says
that the guaranteed layer count after one possible decryption and encryption
meets the receiving output interface's protection requirement. -/
def ProcessingBudget (model : Model Node) : Prop :=
  ∀ node input output header inputTag outputTag,
    input ∈ model.retainedPorts node → output ∈ model.retainedPorts node →
    inputTag ∈ model.tags node → outputTag ∈ model.tags node →
    (inputTag.isSome = true → ∃ wireHeader, model.inputFilter node input wireHeader = true) →
    model.forwardFilter node input output header inputTag outputTag = true →
    model.protectionFloor ⟨node, output⟩ ≤
      (model.protectionFloor ⟨node, input⟩ - tagCost inputTag) + tagCost outputTag

theorem live_port_is_retained (model : Model Node) (node : Node) (port : String) (bytes : Nat)
    (up : model.livePort node port bytes = true) : port ∈ model.retainedPorts node := by
  simp only [Model.livePort, Bool.and_eq_true, List.contains_iff_mem] at up
  exact up.1

theorem forwarding_preserves_protection (model : Model Node) (budget : ProcessingBudget model)
    (node : Node) (input : String) (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result)
    (safe : Protected model ⟨⟨node, input⟩, .input, packet⟩) :
    Protected model ⟨⟨node, result.route.output⟩, .output, result.packet⟩ := by
  obtain ⟨received, sent, filtered, inputUp, outputUp⟩ := forward_evidence model node input packet result accepted
  obtain ⟨inputMessage, inputDepth, inputTag, admitted⟩ :=
    receive_layer_accounting model node input packet result.body result.inputTag received
  obtain ⟨outputMessage, outputDepth, outputTag⟩ :=
    send_layer_accounting model node result.body result.packet result.outputTag sent
  have bounds := budget node input result.route.output result.body.header result.inputTag result.outputTag
    (live_port_is_retained model node input _ inputUp)
    (live_port_is_retained model node result.route.output _ outputUp) inputTag outputTag
    (fun tag => ⟨packet.header, admitted tag⟩) filtered
  intro present
  have original : packet.message.isSome = true := by
    change result.packet.message.isSome = true at present
    rw [outputMessage, ← inputMessage] at present
    exact present
  have prior := safe original
  change model.protectionFloor ⟨node, input⟩ ≤ packet.depth at prior
  change model.protectionFloor ⟨node, result.route.output⟩ ≤ result.packet.depth
  omega

theorem step_preserves_protection (model : Model Node) (budget : ProcessingBudget model)
    (wire : ∀ a b, model.linked a b → model.protectionFloor a = model.protectionFloor b)
    (switch : ∀ a b, model.bridge a b → model.protectionFloor a = model.protectionFloor b)
    {before after : State Node Message} (step : Step model before after)
    (safe : Protected model before) : Protected model after := by
  cases step with
  | wire a b packet link _ _ =>
    simpa only [Protected, wire a b link] using safe
  | switch a b packet connection _ _ =>
    simpa only [Protected, switch a b connection] using safe
  | forward node input packet result accepted =>
    exact forwarding_preserves_protection model budget node input packet result accepted safe

/-- The reusable induction covers every finite execution, including loops and
arbitrary choices of switch outputs. Only local certificates specialize it. -/
theorem executions_preserve_protection (model : Model Node) (budget : ProcessingBudget model)
    (wire : ∀ a b, model.linked a b → model.protectionFloor a = model.protectionFloor b)
    (switch : ∀ a b, model.bridge a b → model.protectionFloor a = model.protectionFloor b)
    {before after : State Node Message} (path : Reach (Step model) before after) :
    Protected model before → Protected model after := by
  induction path with
  | refl => exact id
  | step edge _ ih =>
    intro initial
    exact ih (step_preserves_protection model budget wire switch edge initial)

/-- Denial in both local INPUT and every transit output rejects the arriving
wire packet, including a cipher that might otherwise be decapsulated locally. -/
theorem forward_rejects_denied_ingress (model : Model Node) (node : Node)
    (port : String) (packet : WirePacket Message)
    (localDenied : model.inputFilter node port packet.header = false)
    (transitDenied : ∀ output inputTag outputTag,
      model.forwardFilter node port output packet.header inputTag outputTag = false) :
    model.forward node port packet = none := by
  cases run : model.forward node port packet with
  | none => rfl
  | some result =>
    have facts := forward_evidence model node port packet result run
    have unchanged := receive_with_denied_input_preserves model node port packet result.body
      result.inputTag localDenied facts.1
    have filtered := facts.2.2.1
    rw [unchanged.1, transitDenied] at filtered
    contradiction

/-- A rejected arriving header cannot become an accepted local payload by
decapsulation, because the same INPUT decision guards that operation. -/
theorem deliver_rejects_denied_input (model : Model Node) (node : Node)
    (port : String) (packet : WirePacket Message)
    (denied : model.inputFilter node port packet.header = false) :
    model.deliver node port packet = none := by
  cases received : model.receive node port packet with
  | none => simp [Model.deliver, received]
  | some pair =>
    rcases pair with ⟨body, tag⟩
    have unchanged := receive_with_denied_input_preserves model node port packet body tag denied received
    rw [unchanged.1] at received
    cases route : model.route node packet.header <;> simp [Model.deliver, received, route, denied]

end TDN.Network.Execution
