import TDN.Models.NestedTunnelFrame
import TDN.Models.L2FrameFilter

namespace TDN.MultiProtocolForwarding
open LayeredFrame

structure MACIface where
  logicalIface : Nat
  physicalIface : Nat
  settings : LinkProtection.Config
  transmitAssociation : Option MACsecAssociation
  receiveAssociations : List MACsecAssociation
  validateStrict : Bool
  deriving DecidableEq

structure CarrierIface where
  virtualIface : Nat
  routingIface : Nat
  transmit : Carrier
  localSession : Nat
  deriving DecidableEq

structure HeaderProcessing where
  ipsecHopLimit : Nat → Nat
  carrierHopLimit : Nat → Nat

structure Config where
  ip : DataPlaneForwarding.DataPlaneModel
  macIfaces : List MACIface
  carriers : List CarrierIface
  bridge : Nat → Nat → Prop
  physicalLink : Nat → Nat → Prop
  headerProcessing : Option HeaderProcessing := none
  linkPolicies : List (Nat × LinkAdmission.IfacePolicy) := []
  linkEncoding : Nat → LayeredFrame.Frame → Option LinkAdmission.Frame := fun _ _ => none
  networkBytes : Body → Nat → Option Nat := fun body _ =>
    body.visibleHeader.bind PacketPolicy.Packet.networkBytes

def Config.forwardedFrame (configuration : Config) (frame : Frame) : Frame :=
  match configuration.headerProcessing with
  | none => frame
  | some _ => frame.forwarded

def Config.ipsecFrame (configuration : Config) (iface : Nat) (frame : Frame)
    (association : DataPlaneForwarding.TunnelSAStamp) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := .ipsec association frame.body }
  | some processing =>
      frame.pushHeader (.ipsec association frame.body)
        (some { outerHeader association.sender association.receiver "esp" 0 0 with
          hopLimit := processing.ipsecHopLimit iface })

def Config.macsecFrame (configuration : Config) (frame : Frame)
    (association : MACsecAssociation) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := .macsec association frame.body }
  | some _ => frame.pushHeader (.macsec association frame.body) none

def Config.carrierFrame (configuration : Config) (iface : Nat) (frame : Frame)
    (carrier : Carrier) : Frame :=
  match configuration.headerProcessing with
  | none => { frame with body := .carrier carrier frame.body }
  | some processing =>
      frame.pushHeader (.carrier carrier frame.body)
        (some { outerHeader carrier.source carrier.destination carrier.networkProtocol
          carrier.sourcePort carrier.destinationPort with hopLimit := processing.carrierHopLimit iface })

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
  iface : Nat
  datapathStage : DataPlaneForwarding.DatapathStage
  frame : Frame
  enteredIface : Nat
  authenticated : List Nat
  tracking : String

inductive Action where
  | receive | route | forwardFilter | inputFilter | outputFilter
  | encryptIPsec | decryptIPsec | encryptMACsec | decryptMACsec
  | encapsulate | decapsulate | linkTransmit | bridge | forwardWithoutEncap | deliver | drop
  deriving DecidableEq, Repr

def policyHeader (c : Config) (state : State) (header : PacketPolicy.Packet) : PacketPolicy.Packet :=
  { header with ingress := c.ip.interfaceName state.enteredIface, egress := c.ip.interfaceName state.iface, matchedInboundPolicyIds := state.authenticated, matchedOutboundPolicyIds := (DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies state.iface) header).map DataPlaneForwarding.IpsecPolicy.id, connectionState := state.tracking, networkBytes := c.networkBytes state.frame.body state.frame.payload }

def fullMACsecTransmit (iface : MACIface) (association : MACsecAssociation) (body : Body) : Prop :=
  iface.transmitAssociation = some association ∧
  LinkProtection.transmit iface.settings (some association.keyGeneration) body =
    some (.encrypted association.keyGeneration 0 body)

inductive Step (c : Config) : State → Action → State → Prop
  | receive {s : State} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .received) (visible : c.visibleHeader s.frame = some header)
      (tracking : String) :
      Step c s .receive { s with initialEntry := false, datapathStage := .ingress, enteredIface := s.iface, authenticated := [], tracking := tracking }
  | route {s : State} {header : PacketPolicy.Packet} (route : DataPlaneForwarding.FibRoute)
      (datapathStage : s.datapathStage = .ingress) (visible : c.visibleHeader s.frame = some header)
      (chosen : DataPlaneForwarding.SelectedFibRoute c.ip.routes route header) (entry : route.ingress = s.iface) :
      Step c s .route { s with initialEntry := false, iface := route.egress, datapathStage := .routed, frame := c.forwardedFrame s.frame }
  | routeLocalOutput {s : State} {header : PacketPolicy.Packet} (route : DataPlaneForwarding.FibRoute)
      (datapathStage : s.datapathStage = .localOutput) (visible : c.visibleHeader s.frame = some header)
      (chosen : DataPlaneForwarding.SelectedFibRoute c.ip.routes route header) (entry : route.ingress = s.iface) :
      Step c s .route { s with initialEntry := false, iface := route.egress, datapathStage := .outputRouted }
  | forwardFilter {s : State} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .routed) (visible : c.visibleHeader s.frame = some header)
      (accepted : DataPlaneForwarding.accepts (c.ip.forwardRules s.iface) (c.ip.forwardFallback s.iface)
        (policyHeader c s header)) :
      Step c s .forwardFilter { s with initialEntry := false, datapathStage := .filtered }
  | outputFilter {s : State} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .outputRouted) (visible : c.visibleHeader s.frame = some header)
      (accepted : DataPlaneForwarding.accepts (c.ip.outputRules s.iface) (c.ip.outputFallback s.iface)
        (policyHeader c s header)) :
      Step c s .outputFilter { s with initialEntry := false, datapathStage := .filtered }
  | encryptIPsec {s : State} {header : PacketPolicy.Packet}
      (policy : DataPlaneForwarding.IpsecPolicy) (association : DataPlaneForwarding.InstalledSA)
      (datapathStage : s.datapathStage = .filtered) (visible : c.visibleHeader s.frame = some header)
      (selected : policy ∈ DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies s.iface) header)
      (installed : association ∈ c.ip.egressSAs s.iface)
      (bound : DataPlaneForwarding.saMatchesPolicy association policy) :
      Step c s .encryptIPsec { s with initialEntry := false, datapathStage := .encapsulated, frame := c.ipsecFrame s.iface s.frame (policy.seal association) }
  | routeOuterPacket {s : State} {header : PacketPolicy.Packet} (route : DataPlaneForwarding.FibRoute)
      (datapathStage : s.datapathStage = .encapsulated) (visible : c.visibleHeader s.frame = some header)
      (chosen : DataPlaneForwarding.SelectedFibRoute c.ip.routes route header) (entry : route.ingress = s.iface) :
      Step c s .route { s with initialEntry := false, iface := route.egress, datapathStage := .egressReady }
  | forwardWithoutEncap {s : State} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .filtered) (visible : c.visibleHeader s.frame = some header)
      (noPolicy : DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies s.iface) header = []) :
      Step c s .forwardWithoutEncap { s with initialEntry := false, datapathStage := .egressReady }
  | decryptIPsec {s : State} (policy : DataPlaneForwarding.IpsecPolicy)
      (association : DataPlaneForwarding.InstalledSA) (body : Body) (header : PacketPolicy.Packet)
      (datapathStage : s.datapathStage = .received)
      (encrypted : s.frame.body = .ipsec (policy.seal association) body)
      (configured : policy ∈ c.ip.ingressPolicies s.iface)
      (installed : association ∈ c.ip.ingressSAs s.iface)
      (bound : DataPlaneForwarding.saMatchesPolicy association policy)
      (visible : body.visibleHeader = some header)
      (selected : policy.matches header = true) (tracking : String) :
      Step c s .decryptIPsec { s with initialEntry := false, datapathStage := .ingress, enteredIface := s.iface, frame := c.restoredFrame s.frame body, authenticated := [policy.id], tracking := tracking }
  | inputFilter {s : State} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .ingress) (visible : c.visibleHeader s.frame = some header)
      (addressed : c.ip.localAddress s.iface header.destination)
      (accepted : DataPlaneForwarding.accepts (c.ip.inputRules s.iface) (c.ip.inputFallback s.iface)
        (policyHeader c s header)) :
      Step c s .inputFilter { s with initialEntry := false, datapathStage := .localInput }
  | deliver {s : State} {header : PacketPolicy.Packet} (domain : Nat)
      (datapathStage : s.datapathStage = .localInput) (plain : s.frame.body = .datagram header)
      (recipient : c.ip.ifaceSecurityDomain s.iface = some domain) :
      Step c s .deliver { s with initialEntry := false, datapathStage := .delivered }
  | deliverEthernet {s : State} (header : EthernetHeader) (domain : Nat)
      (datapathStage : s.datapathStage = .received) (plain : s.frame.body = .ethernet header)
      (recipient : c.ip.ifaceSecurityDomain s.iface = some domain) :
      Step c s .deliver { s with initialEntry := false, datapathStage := .delivered }
  | linkTransmit {s : State} (next : Nat) (datapathStage : s.datapathStage = .egressReady)
      (linked : c.physicalLink s.iface next) :
      Step c s .linkTransmit { s with initialEntry := false, iface := next, datapathStage := .received, authenticated := [] }
  | bridge {s : State} (next : Nat) (datapathStage : s.datapathStage = .received)
      (member : c.bridge s.iface next) :
      Step c s .bridge { s with initialEntry := false, iface := next, datapathStage := .egressReady }
  | bridgeOutput {s : State} (next : Nat) (datapathStage : s.datapathStage = .egressReady)
      (member : c.bridge s.iface next) :
      Step c s .bridge { s with initialEntry := false, iface := next, datapathStage := .egressReady }
  | encryptMACsec {s : State} (iface : MACIface) (association : MACsecAssociation)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .egressReady)
      (logical : s.iface = iface.logicalIface)
      (emits : fullMACsecTransmit iface association s.frame.body) :
      Step c s .encryptMACsec { s with initialEntry := false, iface := iface.physicalIface, frame := c.macsecFrame s.frame association }
  | unprotectedMACsec {s : State} (iface : MACIface)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .egressReady)
      (logical : s.iface = iface.logicalIface)
      (enabled : iface.settings.controlledPortEnabled = true)
      (unprotected : iface.settings.protectFrames = false ∨
        iface.settings.encryptFrames = false ∨ iface.settings.confidentialityOffset ≠ 0) :
      Step c s .forwardWithoutEncap { s with initialEntry := false, iface := iface.physicalIface }
  | decryptMACsec {s : State} (iface : MACIface) (association transmitted : MACsecAssociation) (body : Body)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .received)
      (physical : s.iface = iface.physicalIface)
      (encrypted : s.frame.body = .macsec transmitted body)
      (installed : association ∈ iface.receiveAssociations)
      (spi : SameMACWireIdentity transmitted association) :
      Step c s .decryptMACsec { s with initialEntry := false, iface := iface.logicalIface, frame := c.restoredFrame s.frame body, authenticated := [] }
  | uncheckedMACsec {s : State} (iface : MACIface)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .received)
      (physical : s.iface = iface.physicalIface) (unchecked : iface.validateStrict = false) :
      Step c s .forwardWithoutEncap { s with initialEntry := false, iface := iface.logicalIface, authenticated := [] }
  | encapsulate {s : State} (iface : CarrierIface)
      (configured : iface ∈ c.carriers) (datapathStage : s.datapathStage = .egressReady)
      (virtualIface : s.iface = iface.virtualIface) :
      Step c s .encapsulate { s with initialEntry := false, iface := iface.routingIface, datapathStage := .localOutput, enteredIface := iface.routingIface, authenticated := [], frame := c.carrierFrame iface.routingIface s.frame iface.transmit }
  | decapsulate {s : State} (iface : CarrierIface) (body : Body)
      (configured : iface ∈ c.carriers) (datapathStage : s.datapathStage = .localInput)
      (owner : c.ip.owner s.iface = c.ip.owner iface.routingIface)
      (unwrapped : unwrapCarrier iface.transmit.source iface.transmit.destination
        iface.transmit.destinationPort iface.transmit.sourcePort iface.localSession s.frame.body iface.transmit.protocol iface.transmit.networkProtocol = some body) :
      Step c s .decapsulate { s with initialEntry := false, iface := iface.virtualIface, datapathStage := .received, frame := c.restoredFrame s.frame body, authenticated := [] }
  | drop (s : State) : Step c s .drop { s with initialEntry := false, datapathStage := .dropped }

def lts (c : Config) : Cslib.LTS State Action := ⟨Step c⟩

def ForwardsAlongTrace (net : Config) (startPkt : State)
    (actions : List Action) (endPkt : State) : Prop :=
  (lts net).MTr startPkt actions endPkt

lemma step_preserves_payload {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.payload = before.frame.payload ∧
    after.frame.originDomain = before.frame.originDomain := by
  cases mode : c.headerProcessing <;> cases step <;>
    simp [Config.forwardedFrame, Config.ipsecFrame, Config.macsecFrame,
      Config.carrierFrame, Config.restoredFrame, mode, Frame.pushHeader, Frame.popHeader]

theorem all_traces_preserve_payload (c : Config)
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

end TDN.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def Config.LinkPath (c : Config) (iface : Nat) : Prop :=
  (∃ mac ∈ c.macIfaces, mac.physicalIface = iface) ∨
  (∃ next, c.bridge iface next ∨ c.bridge next iface) ∨
  ∃ carrier ∈ c.carriers, carrier.virtualIface = iface

def Config.LinkAdmitted (c : Config) (iface : Nat) (outbound : Bool)
    (frame : LayeredFrame.Frame) : Prop :=
  ∃ encoded, c.linkEncoding iface frame = some encoded ∧ encoded.Describes frame ∧
    LinkAdmission.Admitted c.linkPolicies iface outbound
      (encoded.Packet (if outbound then "" else c.ip.interfaceName iface)
        (if outbound then c.ip.interfaceName iface else ""))

def Config.LinkStepAdmitted (c : Config) (before : State) (action : Action) (after : State) : Prop :=
  (action = .linkTransmit →
    (c.LinkPath before.iface → c.LinkAdmitted before.iface true before.frame) ∧
    (c.LinkPath after.iface → c.LinkAdmitted after.iface false after.frame) ∧
    (c.LinkPath before.iface ∨ c.LinkPath after.iface →
      c.linkEncoding before.iface before.frame = c.linkEncoding after.iface after.frame)) ∧
  (action = .decryptMACsec → c.LinkAdmitted before.iface false before.frame) ∧
  (action = .bridge →
    c.LinkAdmitted before.iface false before.frame ∧
    c.LinkAdmitted after.iface true after.frame) ∧
  (action = .deliver → before.frame.visibleHeader = none → c.LinkPath before.iface →
    c.LinkAdmitted before.iface false before.frame)

end TDN.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def Config.ForwardableHeader (c : Config) (header : PacketPolicy.Packet) : Prop :=
  c.headerProcessing.isSome = true → 1 < header.hopLimit

def Config.HeaderStepAdmitted (c : Config) (before : State) (action : Action) : Prop :=
  action = .route → before.datapathStage = .ingress →
    ∀ header, c.visibleHeader before.frame = some header → c.ForwardableHeader header

def Config.HeaderGenerationKnown (c : Config) (ifaces : List Nat) : Prop :=
  ∃ processing, c.headerProcessing = some processing ∧
    ∀ iface ∈ ifaces,
      0 < processing.ipsecHopLimit iface ∧ processing.ipsecHopLimit iface ≤ 255 ∧
      0 < processing.carrierHopLimit iface ∧ processing.carrierHopLimit iface ≤ 255

def Config.LinkEncodingComplete (c : Config) (state : State) : Prop :=
  c.LinkPath state.iface →
    ∃ encoded, c.linkEncoding state.iface state.frame = some encoded ∧
      encoded.Describes state.frame

end TDN.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

@[simp] lemma Config.forwardedFrame_body (c : Config) (frame : Frame) :
    (c.forwardedFrame frame).body = frame.body := by
  cases mode : c.headerProcessing <;> simp [Config.forwardedFrame, mode]

@[simp] lemma Config.ipsecFrame_body (c : Config) (iface : Nat) (frame : Frame)
    (association : DataPlaneForwarding.TunnelSAStamp) :
    (c.ipsecFrame iface frame association).body = .ipsec association frame.body := by
  unfold Config.ipsecFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma Config.macsecFrame_body (c : Config) (frame : Frame)
    (association : MACsecAssociation) :
    (c.macsecFrame frame association).body = .macsec association frame.body := by
  unfold Config.macsecFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma Config.carrierFrame_body (c : Config) (iface : Nat) (frame : Frame)
    (endpoint : Carrier) :
    (c.carrierFrame iface frame endpoint).body = .carrier endpoint frame.body := by
  unfold Config.carrierFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma Config.restoredFrame_body (c : Config) (frame : Frame) (body : Body) :
    (c.restoredFrame frame body).body = body := by
  unfold Config.restoredFrame
  cases c.headerProcessing <;> rfl

end TDN.MultiProtocolForwarding
