import TDN.Semantics.LayeredFrame

namespace TDN.MultiProtocolExecution
open LayeredFrame

structure MACPort where
  logicalPort : Nat
  physicalPort : Nat
  settings : LinkProtection.Config
  transmitAssociation : Option MACsecAssociation
  receiveAssociations : List MACsecAssociation
  validateStrict : Bool
  deriving DecidableEq

structure CarrierPort where
  virtualPort : Nat
  routingPort : Nat
  transmit : Carrier
  localSession : Nat
  deriving DecidableEq

structure Config where
  ip : Execution.Config
  macPorts : List MACPort
  carriers : List CarrierPort
  bridge : Nat → Nat → Prop
  physicalLink : Nat → Nat → Prop

structure State where
  port : Nat
  phase : Execution.Phase
  frame : Frame
  enteredPort : Nat
  authenticated : List Nat
  tracking : String

inductive Action where
  | receive | route | forwardFilter | inputFilter | outputFilter
  | encryptIPsec | decryptIPsec | encryptMACsec | decryptMACsec
  | encapsulate | decapsulate | wire | bridge | plain | deliver | drop
  deriving DecidableEq, Repr

def policyHeader (c : Config) (state : State) (header : PacketPolicy.Packet) : PacketPolicy.Packet :=
  { header with ingress := c.ip.interfaceName state.enteredPort, egress := c.ip.interfaceName state.port, inboundPolicies := state.authenticated, outboundPolicies := (Execution.selectedAssociations (c.ip.outbound state.port) header).map Execution.Association.id, connectionState := state.tracking }

def fullMACsecTransmit (port : MACPort) (association : MACsecAssociation) (body : Body) : Prop :=
  port.transmitAssociation = some association ∧
  LinkProtection.transmit port.settings (some association.keyGeneration) body =
    some (.encrypted association.keyGeneration 0 body)

inductive Step (c : Config) : State → Action → State → Prop
  | receive {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .received) (visible : s.frame.body.visibleHeader = some header)
      (tracking : String) :
      Step c s .receive { s with phase := .ingress, enteredPort := s.port, authenticated := [], tracking := tracking }
  | route {s : State} {header : PacketPolicy.Packet} (route : Execution.Route)
      (phase : s.phase = .ingress) (visible : s.frame.body.visibleHeader = some header)
      (chosen : Execution.SelectedRoute c.ip.routes route header) (entry : route.ingress = s.port) :
      Step c s .route { s with port := route.egress, phase := .routed }
  | outputRoute {s : State} {header : PacketPolicy.Packet} (route : Execution.Route)
      (phase : s.phase = .localOutput) (visible : s.frame.body.visibleHeader = some header)
      (chosen : Execution.SelectedRoute c.ip.routes route header) (entry : route.ingress = s.port) :
      Step c s .route { s with port := route.egress, phase := .outputRouted }
  | forwardFilter {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .routed) (visible : s.frame.body.visibleHeader = some header)
      (accepted : Execution.accepts (c.ip.forwardRules s.port) (c.ip.forwardFallback s.port)
        (policyHeader c s header)) :
      Step c s .forwardFilter { s with phase := .filtered }
  | outputFilter {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .outputRouted) (visible : s.frame.body.visibleHeader = some header)
      (accepted : Execution.accepts (c.ip.outputRules s.port) (c.ip.outputFallback s.port)
        (policyHeader c s header)) :
      Step c s .outputFilter { s with phase := .filtered }
  | encryptIPsec {s : State} {header : PacketPolicy.Packet}
      (policy : Execution.Association) (association : Execution.SecurityAssociation)
      (phase : s.phase = .filtered) (visible : s.frame.body.visibleHeader = some header)
      (selected : policy ∈ Execution.selectedAssociations (c.ip.outbound s.port) header)
      (installed : association ∈ c.ip.outboundStates s.port)
      (bound : Execution.StateBindsPolicy association policy) :
      Step c s .encryptIPsec { s with phase := .encapsulated, frame := { s.frame with body := .ipsec (policy.seal association) s.frame.body } }
  | outerRoute {s : State} {header : PacketPolicy.Packet} (route : Execution.Route)
      (phase : s.phase = .encapsulated) (visible : s.frame.body.visibleHeader = some header)
      (chosen : Execution.SelectedRoute c.ip.routes route header) (entry : route.ingress = s.port) :
      Step c s .route { s with port := route.egress, phase := .ready }
  | plain {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .filtered) (visible : s.frame.body.visibleHeader = some header)
      (noPolicy : Execution.selectedAssociations (c.ip.outbound s.port) header = []) :
      Step c s .plain { s with phase := .ready }
  | decryptIPsec {s : State} (policy : Execution.Association)
      (association : Execution.SecurityAssociation) (body : Body) (header : PacketPolicy.Packet)
      (phase : s.phase = .received)
      (encrypted : s.frame.body = .ipsec (policy.seal association) body)
      (configured : policy ∈ c.ip.inbound s.port)
      (installed : association ∈ c.ip.inboundStates s.port)
      (bound : Execution.StateBindsPolicy association policy)
      (visible : body.visibleHeader = some header)
      (selected : policy.matches header = true) (tracking : String) :
      Step c s .decryptIPsec { s with phase := .ingress, enteredPort := s.port, frame := { s.frame with body := body }, authenticated := [policy.id], tracking := tracking }
  | inputFilter {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .ingress) (visible : s.frame.body.visibleHeader = some header)
      (addressed : c.ip.localAddress s.port header.destination)
      (accepted : Execution.accepts (c.ip.inputRules s.port) (c.ip.inputFallback s.port)
        (policyHeader c s header)) :
      Step c s .inputFilter { s with phase := .localInput }
  | deliver {s : State} {header : PacketPolicy.Packet} (domain : Nat)
      (phase : s.phase = .localInput) (plain : s.frame.body = .datagram header)
      (recipient : c.ip.recipientDomain s.port = some domain) :
      Step c s .deliver { s with phase := .delivered }
  | deliverEthernet {s : State} (header : EthernetHeader) (domain : Nat)
      (phase : s.phase = .received) (plain : s.frame.body = .ethernet header)
      (recipient : c.ip.recipientDomain s.port = some domain) :
      Step c s .deliver { s with phase := .delivered }
  | wire {s : State} (next : Nat) (phase : s.phase = .ready)
      (linked : c.physicalLink s.port next) :
      Step c s .wire { s with port := next, phase := .received, authenticated := [] }
  | bridge {s : State} (next : Nat) (phase : s.phase = .received)
      (member : c.bridge s.port next) :
      Step c s .bridge { s with port := next, phase := .ready }
  | bridgeOutput {s : State} (next : Nat) (phase : s.phase = .ready)
      (member : c.bridge s.port next) :
      Step c s .bridge { s with port := next, phase := .ready }
  | encryptMACsec {s : State} (port : MACPort) (association : MACsecAssociation)
      (configured : port ∈ c.macPorts) (phase : s.phase = .ready)
      (logical : s.port = port.logicalPort)
      (emits : fullMACsecTransmit port association s.frame.body) :
      Step c s .encryptMACsec { s with port := port.physicalPort, frame := { s.frame with body := .macsec association s.frame.body } }
  | unprotectedMACsec {s : State} (port : MACPort)
      (configured : port ∈ c.macPorts) (phase : s.phase = .ready)
      (logical : s.port = port.logicalPort)
      (enabled : port.settings.controlledPortEnabled = true)
      (unprotected : port.settings.protectFrames = false ∨
        port.settings.encryptFrames = false ∨ port.settings.confidentialityOffset ≠ 0) :
      Step c s .plain { s with port := port.physicalPort }
  | decryptMACsec {s : State} (port : MACPort) (association transmitted : MACsecAssociation) (body : Body)
      (configured : port ∈ c.macPorts) (phase : s.phase = .received)
      (physical : s.port = port.physicalPort)
      (encrypted : s.frame.body = .macsec transmitted body)
      (installed : association ∈ port.receiveAssociations)
      (wireIdentity : SameMACWireIdentity transmitted association) :
      Step c s .decryptMACsec { s with port := port.logicalPort, frame := { s.frame with body := body }, authenticated := [] }
  | uncheckedMACsec {s : State} (port : MACPort)
      (configured : port ∈ c.macPorts) (phase : s.phase = .received)
      (physical : s.port = port.physicalPort) (unchecked : port.validateStrict = false) :
      Step c s .plain { s with port := port.logicalPort, authenticated := [] }
  | encapsulate {s : State} (port : CarrierPort)
      (configured : port ∈ c.carriers) (phase : s.phase = .ready)
      (virtualPort : s.port = port.virtualPort) :
      Step c s .encapsulate { s with port := port.routingPort, phase := .localOutput, enteredPort := port.routingPort, authenticated := [], frame := { s.frame with body := .carrier port.transmit s.frame.body } }
  | decapsulate {s : State} (port : CarrierPort) (body : Body)
      (configured : port ∈ c.carriers) (phase : s.phase = .localInput)
      (owner : c.ip.owner s.port = c.ip.owner port.routingPort)
      (unwrapped : unwrapCarrier port.transmit.source port.transmit.destination
        port.transmit.destinationPort port.transmit.sourcePort port.localSession s.frame.body = some body) :
      Step c s .decapsulate { s with port := port.virtualPort, phase := .received, frame := { s.frame with body := body }, authenticated := [] }
  | drop (s : State) : Step c s .drop { s with phase := .dropped }

def lts (c : Config) : Cslib.LTS State Action := ⟨Step c⟩

lemma step_preserves_payload {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.payload = before.frame.payload ∧
    after.frame.originDomain = before.frame.originDomain := by
  cases step <;> exact ⟨rfl, rfl⟩

theorem all_executions_preserve_payload (c : Config)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) :
    after.frame.payload = before.frame.payload ∧
    after.frame.originDomain = before.frame.originDomain := by
  have preserved : (lts c).TrInv (fun state =>
      state.frame.payload = before.frame.payload ∧
      state.frame.originDomain = before.frame.originDomain) := by
    intro first action last step valid
    obtain ⟨payload, origin⟩ := step_preserves_payload step
    exact ⟨payload.trans valid.1, origin.trans valid.2⟩
  exact Cslib.LTS.mtrInv_of_trInv preserved before actions after run ⟨rfl, rfl⟩

end TDN.MultiProtocolExecution
