import TDN.Semantics.LayeredFrame
import TDN.Semantics.LinkAdmission

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

structure HeaderProcessing where
  ipsecHopLimit : Nat → Nat
  carrierHopLimit : Nat → Nat

structure Config where
  ip : Execution.Config
  macPorts : List MACPort
  carriers : List CarrierPort
  bridge : Nat → Nat → Prop
  physicalLink : Nat → Nat → Prop
  headerProcessing : Option HeaderProcessing := none
  linkPolicies : List (Nat × LinkAdmission.PortPolicy) := []
  linkEncoding : Nat → LayeredFrame.Frame → Option LinkAdmission.Frame := fun _ _ => none
  networkBytes : Body → Nat → Option Nat := fun body _ =>
    body.visibleHeader.bind PacketPolicy.Packet.networkBytes

def Config.forwardedFrame (configuration : Config) (frame : Frame) : Frame :=
  match configuration.headerProcessing with
  | none => frame
  | some _ => frame.forwarded

def Config.ipsecFrame (configuration : Config) (port : Nat) (frame : Frame)
    (association : Execution.Seal) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := .ipsec association frame.body }
  | some processing =>
      frame.pushHeader (.ipsec association frame.body)
        (some { outerHeader association.sender association.receiver "esp" 0 0 with
          hopLimit := processing.ipsecHopLimit port })

def Config.macsecFrame (configuration : Config) (frame : Frame)
    (association : MACsecAssociation) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := .macsec association frame.body }
  | some _ => frame.pushHeader (.macsec association frame.body) none

def Config.carrierFrame (configuration : Config) (port : Nat) (frame : Frame)
    (carrier : Carrier) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := .carrier carrier frame.body }
  | some processing =>
      frame.pushHeader (.carrier carrier frame.body)
        (some { outerHeader carrier.source carrier.destination carrier.networkProtocol
          carrier.sourcePort carrier.destinationPort with hopLimit := processing.carrierHopLimit port })

def Config.restoredFrame (configuration : Config) (frame : Frame) (body : Body) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := body }
  | some _ => frame.popHeader body

def Config.visibleHeader (configuration : Config) (frame : Frame) : Option PacketPolicy.Packet :=
  match configuration.headerProcessing with
  | none => frame.body.visibleHeader
  | some _ => frame.visibleHeader

structure State where
  initialEntry : Bool := false
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
  { header with ingress := c.ip.interfaceName state.enteredPort, egress := c.ip.interfaceName state.port, inboundPolicies := state.authenticated, outboundPolicies := (Execution.selectedAssociations (c.ip.outbound state.port) header).map Execution.Association.id, connectionState := state.tracking, networkBytes := c.networkBytes state.frame.body state.frame.payload }

def fullMACsecTransmit (port : MACPort) (association : MACsecAssociation) (body : Body) : Prop :=
  port.transmitAssociation = some association ∧
  LinkProtection.transmit port.settings (some association.keyGeneration) body =
    some (.encrypted association.keyGeneration 0 body)

inductive Step (c : Config) : State → Action → State → Prop
  | receive {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .received) (visible : c.visibleHeader s.frame = some header)
      (tracking : String) :
      Step c s .receive { s with initialEntry := false, phase := .ingress, enteredPort := s.port, authenticated := [], tracking := tracking }
  | route {s : State} {header : PacketPolicy.Packet} (route : Execution.Route)
      (phase : s.phase = .ingress) (visible : c.visibleHeader s.frame = some header)
      (chosen : Execution.SelectedRoute c.ip.routes route header) (entry : route.ingress = s.port) :
      Step c s .route { s with initialEntry := false, port := route.egress, phase := .routed, frame := c.forwardedFrame s.frame }
  | outputRoute {s : State} {header : PacketPolicy.Packet} (route : Execution.Route)
      (phase : s.phase = .localOutput) (visible : c.visibleHeader s.frame = some header)
      (chosen : Execution.SelectedRoute c.ip.routes route header) (entry : route.ingress = s.port) :
      Step c s .route { s with initialEntry := false, port := route.egress, phase := .outputRouted }
  | forwardFilter {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .routed) (visible : c.visibleHeader s.frame = some header)
      (accepted : Execution.accepts (c.ip.forwardRules s.port) (c.ip.forwardFallback s.port)
        (policyHeader c s header)) :
      Step c s .forwardFilter { s with initialEntry := false, phase := .filtered }
  | outputFilter {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .outputRouted) (visible : c.visibleHeader s.frame = some header)
      (accepted : Execution.accepts (c.ip.outputRules s.port) (c.ip.outputFallback s.port)
        (policyHeader c s header)) :
      Step c s .outputFilter { s with initialEntry := false, phase := .filtered }
  | encryptIPsec {s : State} {header : PacketPolicy.Packet}
      (policy : Execution.Association) (association : Execution.SecurityAssociation)
      (phase : s.phase = .filtered) (visible : c.visibleHeader s.frame = some header)
      (selected : policy ∈ Execution.selectedAssociations (c.ip.outbound s.port) header)
      (installed : association ∈ c.ip.outboundStates s.port)
      (bound : Execution.StateBindsPolicy association policy) :
      Step c s .encryptIPsec { s with initialEntry := false, phase := .encapsulated, frame := c.ipsecFrame s.port s.frame (policy.seal association) }
  | outerRoute {s : State} {header : PacketPolicy.Packet} (route : Execution.Route)
      (phase : s.phase = .encapsulated) (visible : c.visibleHeader s.frame = some header)
      (chosen : Execution.SelectedRoute c.ip.routes route header) (entry : route.ingress = s.port) :
      Step c s .route { s with initialEntry := false, port := route.egress, phase := .ready }
  | plain {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .filtered) (visible : c.visibleHeader s.frame = some header)
      (noPolicy : Execution.selectedAssociations (c.ip.outbound s.port) header = []) :
      Step c s .plain { s with initialEntry := false, phase := .ready }
  | decryptIPsec {s : State} (policy : Execution.Association)
      (association : Execution.SecurityAssociation) (body : Body) (header : PacketPolicy.Packet)
      (phase : s.phase = .received)
      (encrypted : s.frame.body = .ipsec (policy.seal association) body)
      (configured : policy ∈ c.ip.inbound s.port)
      (installed : association ∈ c.ip.inboundStates s.port)
      (bound : Execution.StateBindsPolicy association policy)
      (visible : body.visibleHeader = some header)
      (selected : policy.matches header = true) (tracking : String) :
      Step c s .decryptIPsec { s with initialEntry := false, phase := .ingress, enteredPort := s.port, frame := c.restoredFrame s.frame body, authenticated := [policy.id], tracking := tracking }
  | inputFilter {s : State} {header : PacketPolicy.Packet}
      (phase : s.phase = .ingress) (visible : c.visibleHeader s.frame = some header)
      (addressed : c.ip.localAddress s.port header.destination)
      (accepted : Execution.accepts (c.ip.inputRules s.port) (c.ip.inputFallback s.port)
        (policyHeader c s header)) :
      Step c s .inputFilter { s with initialEntry := false, phase := .localInput }
  | deliver {s : State} {header : PacketPolicy.Packet} (domain : Nat)
      (phase : s.phase = .localInput) (plain : s.frame.body = .datagram header)
      (recipient : c.ip.recipientDomain s.port = some domain) :
      Step c s .deliver { s with initialEntry := false, phase := .delivered }
  | deliverEthernet {s : State} (header : EthernetHeader) (domain : Nat)
      (phase : s.phase = .received) (plain : s.frame.body = .ethernet header)
      (recipient : c.ip.recipientDomain s.port = some domain) :
      Step c s .deliver { s with initialEntry := false, phase := .delivered }
  | wire {s : State} (next : Nat) (phase : s.phase = .ready)
      (linked : c.physicalLink s.port next) :
      Step c s .wire { s with initialEntry := false, port := next, phase := .received, authenticated := [] }
  | bridge {s : State} (next : Nat) (phase : s.phase = .received)
      (member : c.bridge s.port next) :
      Step c s .bridge { s with initialEntry := false, port := next, phase := .ready }
  | bridgeOutput {s : State} (next : Nat) (phase : s.phase = .ready)
      (member : c.bridge s.port next) :
      Step c s .bridge { s with initialEntry := false, port := next, phase := .ready }
  | encryptMACsec {s : State} (port : MACPort) (association : MACsecAssociation)
      (configured : port ∈ c.macPorts) (phase : s.phase = .ready)
      (logical : s.port = port.logicalPort)
      (emits : fullMACsecTransmit port association s.frame.body) :
      Step c s .encryptMACsec { s with initialEntry := false, port := port.physicalPort, frame := c.macsecFrame s.frame association }
  | unprotectedMACsec {s : State} (port : MACPort)
      (configured : port ∈ c.macPorts) (phase : s.phase = .ready)
      (logical : s.port = port.logicalPort)
      (enabled : port.settings.controlledPortEnabled = true)
      (unprotected : port.settings.protectFrames = false ∨
        port.settings.encryptFrames = false ∨ port.settings.confidentialityOffset ≠ 0) :
      Step c s .plain { s with initialEntry := false, port := port.physicalPort }
  | decryptMACsec {s : State} (port : MACPort) (association transmitted : MACsecAssociation) (body : Body)
      (configured : port ∈ c.macPorts) (phase : s.phase = .received)
      (physical : s.port = port.physicalPort)
      (encrypted : s.frame.body = .macsec transmitted body)
      (installed : association ∈ port.receiveAssociations)
      (wireIdentity : SameMACWireIdentity transmitted association) :
      Step c s .decryptMACsec { s with initialEntry := false, port := port.logicalPort, frame := c.restoredFrame s.frame body, authenticated := [] }
  | uncheckedMACsec {s : State} (port : MACPort)
      (configured : port ∈ c.macPorts) (phase : s.phase = .received)
      (physical : s.port = port.physicalPort) (unchecked : port.validateStrict = false) :
      Step c s .plain { s with initialEntry := false, port := port.logicalPort, authenticated := [] }
  | encapsulate {s : State} (port : CarrierPort)
      (configured : port ∈ c.carriers) (phase : s.phase = .ready)
      (virtualPort : s.port = port.virtualPort) :
      Step c s .encapsulate { s with initialEntry := false, port := port.routingPort, phase := .localOutput, enteredPort := port.routingPort, authenticated := [], frame := c.carrierFrame port.routingPort s.frame port.transmit }
  | decapsulate {s : State} (port : CarrierPort) (body : Body)
      (configured : port ∈ c.carriers) (phase : s.phase = .localInput)
      (owner : c.ip.owner s.port = c.ip.owner port.routingPort)
      (unwrapped : unwrapCarrier port.transmit.source port.transmit.destination
        port.transmit.destinationPort port.transmit.sourcePort port.localSession s.frame.body port.transmit.protocol port.transmit.networkProtocol = some body) :
      Step c s .decapsulate { s with initialEntry := false, port := port.virtualPort, phase := .received, frame := c.restoredFrame s.frame body, authenticated := [] }
  | drop (s : State) : Step c s .drop { s with initialEntry := false, phase := .dropped }

def lts (c : Config) : Cslib.LTS State Action := ⟨Step c⟩

lemma step_preserves_payload {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.payload = before.frame.payload ∧
    after.frame.originDomain = before.frame.originDomain := by
  cases mode : c.headerProcessing <;> cases step <;>
    simp [Config.forwardedFrame, Config.ipsecFrame, Config.macsecFrame,
      Config.carrierFrame, Config.restoredFrame, mode, Frame.pushHeader, Frame.popHeader]

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

namespace TDN.MultiProtocolExecution
open LayeredFrame

def Config.LinkPath (c : Config) (port : Nat) : Prop :=
  (∃ mac ∈ c.macPorts, mac.physicalPort = port) ∨
  (∃ next, c.bridge port next ∨ c.bridge next port) ∨
  ∃ carrier ∈ c.carriers, carrier.virtualPort = port

def Config.LinkAdmitted (c : Config) (port : Nat) (outbound : Bool)
    (frame : LayeredFrame.Frame) : Prop :=
  ∃ encoded, c.linkEncoding port frame = some encoded ∧ encoded.Describes frame ∧
    LinkAdmission.Admitted c.linkPolicies port outbound
      (encoded.Packet (if outbound then "" else c.ip.interfaceName port)
        (if outbound then c.ip.interfaceName port else ""))

def Config.LinkStepAdmitted (c : Config) (before : State) (action : Action) (after : State) : Prop :=
  (action = .wire →
    (c.LinkPath before.port → c.LinkAdmitted before.port true before.frame) ∧
    (c.LinkPath after.port → c.LinkAdmitted after.port false after.frame) ∧
    (c.LinkPath before.port ∨ c.LinkPath after.port →
      c.linkEncoding before.port before.frame = c.linkEncoding after.port after.frame)) ∧
  (action = .decryptMACsec → c.LinkAdmitted before.port false before.frame) ∧
  (action = .bridge →
    c.LinkAdmitted before.port false before.frame ∧
    c.LinkAdmitted after.port true after.frame) ∧
  (action = .deliver → before.frame.visibleHeader = none → c.LinkPath before.port →
    c.LinkAdmitted before.port false before.frame)

end TDN.MultiProtocolExecution

namespace TDN.MultiProtocolExecution
open LayeredFrame

def Config.ForwardableHeader (c : Config) (header : PacketPolicy.Packet) : Prop :=
  c.headerProcessing.isSome = true → 1 < header.hopLimit

def Config.HeaderStepAdmitted (c : Config) (before : State) (action : Action) : Prop :=
  action = .route → before.phase = .ingress →
    ∀ header, c.visibleHeader before.frame = some header → c.ForwardableHeader header

def Config.HeaderGenerationKnown (c : Config) (ports : List Nat) : Prop :=
  ∃ processing, c.headerProcessing = some processing ∧
    ∀ port ∈ ports,
      0 < processing.ipsecHopLimit port ∧ processing.ipsecHopLimit port ≤ 255 ∧
      0 < processing.carrierHopLimit port ∧ processing.carrierHopLimit port ≤ 255

def Config.LinkEncodingComplete (c : Config) (state : State) : Prop :=
  c.LinkPath state.port →
    ∃ encoded, c.linkEncoding state.port state.frame = some encoded ∧
      encoded.Describes state.frame

end TDN.MultiProtocolExecution

namespace TDN.MultiProtocolExecution
open LayeredFrame

@[simp] lemma Config.forwardedFrame_body (c : Config) (frame : Frame) :
    (c.forwardedFrame frame).body = frame.body := by
  cases mode : c.headerProcessing <;> simp [Config.forwardedFrame, mode]

@[simp] lemma Config.ipsecFrame_body (c : Config) (port : Nat) (frame : Frame)
    (association : Execution.Seal) :
    (c.ipsecFrame port frame association).body = .ipsec association frame.body := by
  unfold Config.ipsecFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma Config.macsecFrame_body (c : Config) (frame : Frame)
    (association : MACsecAssociation) :
    (c.macsecFrame frame association).body = .macsec association frame.body := by
  unfold Config.macsecFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma Config.carrierFrame_body (c : Config) (port : Nat) (frame : Frame)
    (endpoint : Carrier) :
    (c.carrierFrame port frame endpoint).body = .carrier endpoint frame.body := by
  unfold Config.carrierFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma Config.restoredFrame_body (c : Config) (frame : Frame) (body : Body) :
    (c.restoredFrame frame body).body = body := by
  unfold Config.restoredFrame
  cases c.headerProcessing <;> rfl

end TDN.MultiProtocolExecution
