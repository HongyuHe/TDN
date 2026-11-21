import TDN.Models.NestedTunnelFrame
import TDN.Models.L2FrameFilter

namespace TDN.MultiProtocolForwarding
open LayeredFrame

structure MACIface where
  logicalIface : Nat
  physicalIface : Nat
  settings : LinkProtection.MacsecPortConfig
  transmitAssociation : Option MacsecAssociation
  receiveAssociations : List MacsecAssociation
  validateStrict : Bool
  deriving DecidableEq

structure CarrierIface where
  virtualIface : Nat
  routingIface : Nat
  transmit : EthernetTunnelHeader
  localSession : Nat
  deriving DecidableEq

structure HeaderProcessing where
  ipsecHopLimit : Nat → Nat
  carrierHopLimit : Nat → Nat

structure TunnelForwardingModel where
  ip : DataPlaneForwarding.DataPlaneModel
  macIfaces : List MACIface
  carriers : List CarrierIface
  bridge : Nat → Nat → Prop
  physicalLink : Nat → Nat → Prop
  headerProcessing : Option HeaderProcessing := none
  linkPolicies : List (Nat × LinkAdmission.IfacePolicy) := []
  linkEncoding : Nat → LayeredFrame.TunnelFrame → Option LinkAdmission.EthernetFrame := fun _ _ => none
  networkBytes : Body → Nat → Option Nat := fun body _ =>
    body.visibleHeader.bind PacketPolicy.Packet.networkBytes

def TunnelForwardingModel.forwardedFrame (configuration : TunnelForwardingModel) (frame : TunnelFrame) : TunnelFrame :=
  match configuration.headerProcessing with
  | none => frame
  | some _ => frame.forwarded

def TunnelForwardingModel.ipsecFrame (configuration : TunnelForwardingModel) (iface : Nat) (frame : TunnelFrame)
    (association : DataPlaneForwarding.TunnelSaStamp) : TunnelFrame :=
  match configuration.headerProcessing with
  | none => { frame with body := .ipsec association frame.body }
  | some processing =>
      frame.pushHeader (.ipsec association frame.body)
        (some { outerHeader association.sender association.receiver "esp" 0 0 with
          hopLimit := processing.ipsecHopLimit iface })

def TunnelForwardingModel.macsecFrame (configuration : TunnelForwardingModel) (frame : TunnelFrame)
    (association : MacsecAssociation) : TunnelFrame :=
  match configuration.headerProcessing with
  | none => { frame with body := .macsec association frame.body }
  | some _ => frame.pushHeader (.macsec association frame.body) none

def TunnelForwardingModel.macsecPduFrame (configuration : TunnelForwardingModel) (frame : TunnelFrame)
    (association : MacsecAssociation) (encryptFrames : Bool) (confidentialityOffset : Nat) : TunnelFrame :=
  match configuration.headerProcessing with
  | none => { frame with body := .macsecPdu association encryptFrames confidentialityOffset frame.body }
  | some _ => frame.pushHeader (.macsecPdu association encryptFrames confidentialityOffset frame.body) none

def TunnelForwardingModel.carrierFrame (configuration : TunnelForwardingModel) (iface : Nat) (frame : TunnelFrame)
    (carrier : EthernetTunnelHeader) : TunnelFrame :=
  match configuration.headerProcessing with
  | none => { frame with body := .carrier carrier frame.body }
  | some processing =>
      frame.pushHeader (.carrier carrier frame.body)
        (some { outerHeader carrier.source carrier.destination carrier.networkProtocol
          carrier.sourcePort carrier.destinationPort with hopLimit := processing.carrierHopLimit iface })

def TunnelForwardingModel.restoredFrame (configuration : TunnelForwardingModel) (frame : TunnelFrame) (body : Body) : TunnelFrame :=
  match configuration.headerProcessing with
  | none => { frame with body := body }
  | some _ => frame.popHeader body

def TunnelForwardingModel.visibleHeader (configuration : TunnelForwardingModel) (frame : TunnelFrame) : Option PacketPolicy.Packet :=
  match configuration.headerProcessing with
  | none => frame.body.visibleHeader
  | some _ => frame.visibleHeader

structure TunnelForwardingState where
  initialEntry : Bool := false
  iface : Nat
  datapathStage : DataPlaneForwarding.DatapathStage
  frame : TunnelFrame
  enteredIface : Nat
  authenticated : List Nat
  tracking : String

inductive TunnelForwardingAction where
  | receive | route | forwardFilter | inputFilter | outputFilter
  | encryptIPsec | decryptIPsec | encryptMACsec | decryptMACsec | protectMACsec | validateMACsec
  | encapsulate | decapsulate | linkTransmit | bridge | forwardWithoutEncap | deliver | drop
  deriving DecidableEq, Repr

def policyHeader (c : TunnelForwardingModel) (state : TunnelForwardingState) (header : PacketPolicy.Packet) : PacketPolicy.Packet :=
  { header with ingress := c.ip.interfaceName state.enteredIface, egress := c.ip.interfaceName state.iface, matchedInboundPolicyIds := state.authenticated, matchedOutboundPolicyIds := (DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies state.iface) header).map DataPlaneForwarding.IpsecPolicy.id, connectionState := state.tracking, networkBytes := c.networkBytes state.frame.body state.frame.payload }

def fullMACsecTransmit (iface : MACIface) (association : MacsecAssociation) (body : Body) : Prop :=
  iface.transmitAssociation = some association ∧
  LinkProtection.transmit iface.settings (some association.keyGeneration) body =
    some (.encrypted association.keyGeneration 0 body)

inductive TunnelForwardingStep (c : TunnelForwardingModel) : TunnelForwardingState → TunnelForwardingAction → TunnelForwardingState → Prop
  | receive {s : TunnelForwardingState} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .received) (visible : c.visibleHeader s.frame = some header)
      (tracking : String) :
      TunnelForwardingStep c s .receive { s with initialEntry := false, datapathStage := .ingress, enteredIface := s.iface, authenticated := [], tracking := tracking }
  | route {s : TunnelForwardingState} {header : PacketPolicy.Packet} (route : DataPlaneForwarding.FibRoute)
      (datapathStage : s.datapathStage = .ingress) (visible : c.visibleHeader s.frame = some header)
      (chosen : DataPlaneForwarding.SelectedFibRoute c.ip.routes route header) (entry : route.ingress = s.iface) :
      TunnelForwardingStep c s .route { s with initialEntry := false, iface := route.egress, datapathStage := .routed, frame := c.forwardedFrame s.frame }
  | routeLocalOutput {s : TunnelForwardingState} {header : PacketPolicy.Packet} (route : DataPlaneForwarding.FibRoute)
      (datapathStage : s.datapathStage = .localOutput) (visible : c.visibleHeader s.frame = some header)
      (chosen : DataPlaneForwarding.SelectedFibRoute c.ip.routes route header) (entry : route.ingress = s.iface) :
      TunnelForwardingStep c s .route { s with initialEntry := false, iface := route.egress, datapathStage := .outputRouted }
  | forwardFilter {s : TunnelForwardingState} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .routed) (visible : c.visibleHeader s.frame = some header)
      (accepted : PacketPolicy.AclAllows (c.ip.forwardRules s.iface) (c.ip.forwardFallback s.iface)
        (policyHeader c s header)) :
      TunnelForwardingStep c s .forwardFilter { s with initialEntry := false, datapathStage := .filtered }
  | outputFilter {s : TunnelForwardingState} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .outputRouted) (visible : c.visibleHeader s.frame = some header)
      (accepted : PacketPolicy.AclAllows (c.ip.outputRules s.iface) (c.ip.outputFallback s.iface)
        (policyHeader c s header)) :
      TunnelForwardingStep c s .outputFilter { s with initialEntry := false, datapathStage := .filtered }
  | encryptIPsec {s : TunnelForwardingState} {header : PacketPolicy.Packet}
      (policy : DataPlaneForwarding.IpsecPolicy) (association : DataPlaneForwarding.InstalledSa)
      (datapathStage : s.datapathStage = .filtered) (visible : c.visibleHeader s.frame = some header)
      (selected : policy ∈ DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies s.iface) header)
      (installed : association ∈ c.ip.egressSAs s.iface)
      (bound : DataPlaneForwarding.saMatchesPolicy association policy) :
      TunnelForwardingStep c s .encryptIPsec { s with initialEntry := false, datapathStage := .encapsulated, frame := c.ipsecFrame s.iface s.frame (policy.seal association) }
  | routeOuterPacket {s : TunnelForwardingState} {header : PacketPolicy.Packet} (route : DataPlaneForwarding.FibRoute)
      (datapathStage : s.datapathStage = .encapsulated) (visible : c.visibleHeader s.frame = some header)
      (chosen : DataPlaneForwarding.SelectedFibRoute c.ip.routes route header) (entry : route.ingress = s.iface) :
      TunnelForwardingStep c s .route { s with initialEntry := false, iface := route.egress, datapathStage := .egressReady }
  | forwardWithoutEncap {s : TunnelForwardingState} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .filtered) (visible : c.visibleHeader s.frame = some header)
      (noPolicy : DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies s.iface) header = []) :
      TunnelForwardingStep c s .forwardWithoutEncap { s with initialEntry := false, datapathStage := .egressReady }
  | decryptIPsec {s : TunnelForwardingState} (policy : DataPlaneForwarding.IpsecPolicy)
      (association : DataPlaneForwarding.InstalledSa) (body : Body) (header : PacketPolicy.Packet)
      (datapathStage : s.datapathStage = .received)
      (encrypted : s.frame.body = .ipsec (policy.seal association) body)
      (configured : policy ∈ c.ip.ingressPolicies s.iface)
      (installed : association ∈ c.ip.ingressSAs s.iface)
      (bound : DataPlaneForwarding.saMatchesPolicy association policy)
      (visible : body.visibleHeader = some header)
      (selected : policy.matches header = true) (tracking : String) :
      TunnelForwardingStep c s .decryptIPsec { s with initialEntry := false, datapathStage := .ingress, enteredIface := s.iface, frame := c.restoredFrame s.frame body, authenticated := [policy.id], tracking := tracking }
  | inputFilter {s : TunnelForwardingState} {header : PacketPolicy.Packet}
      (datapathStage : s.datapathStage = .ingress) (visible : c.visibleHeader s.frame = some header)
      (addressed : c.ip.localAddress s.iface header.destination)
      (accepted : PacketPolicy.AclAllows (c.ip.inputRules s.iface) (c.ip.inputFallback s.iface)
        (policyHeader c s header)) :
      TunnelForwardingStep c s .inputFilter { s with initialEntry := false, datapathStage := .localInput }
  | deliver {s : TunnelForwardingState} {header : PacketPolicy.Packet} (domain : Nat)
      (datapathStage : s.datapathStage = .localInput) (plain : s.frame.body = .datagram header)
      (recipient : c.ip.ifaceSecurityDomain s.iface = some domain) :
      TunnelForwardingStep c s .deliver { s with initialEntry := false, datapathStage := .delivered }
  | deliverEthernet {s : TunnelForwardingState} (header : EthernetHeader) (domain : Nat)
      (datapathStage : s.datapathStage = .received) (plain : s.frame.body = .ethernet header)
      (recipient : c.ip.ifaceSecurityDomain s.iface = some domain) :
      TunnelForwardingStep c s .deliver { s with initialEntry := false, datapathStage := .delivered }
  | linkTransmit {s : TunnelForwardingState} (next : Nat) (datapathStage : s.datapathStage = .egressReady)
      (linked : c.physicalLink s.iface next) :
      TunnelForwardingStep c s .linkTransmit { s with initialEntry := false, iface := next, datapathStage := .received, authenticated := [] }
  | bridge {s : TunnelForwardingState} (next : Nat) (datapathStage : s.datapathStage = .received)
      (member : c.bridge s.iface next) :
      TunnelForwardingStep c s .bridge { s with initialEntry := false, iface := next, datapathStage := .egressReady }
  | bridgeOutput {s : TunnelForwardingState} (next : Nat) (datapathStage : s.datapathStage = .egressReady)
      (member : c.bridge s.iface next) :
      TunnelForwardingStep c s .bridge { s with initialEntry := false, iface := next, datapathStage := .egressReady }
  | encryptMACsec {s : TunnelForwardingState} (iface : MACIface) (association : MacsecAssociation)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .egressReady)
      (logical : s.iface = iface.logicalIface)
      (emits : fullMACsecTransmit iface association s.frame.body) :
      TunnelForwardingStep c s .encryptMACsec { s with initialEntry := false, iface := iface.physicalIface, frame := c.macsecFrame s.frame association }
  | unprotectedMACsec {s : TunnelForwardingState} (iface : MACIface)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .egressReady)
      (logical : s.iface = iface.logicalIface)
      (enabled : iface.settings.controlledPortEnabled = true)
      (unprotected : iface.settings.protectFrames = false) :
      TunnelForwardingStep c s .forwardWithoutEncap { s with initialEntry := false, iface := iface.physicalIface }
  | protectMACsec {s : TunnelForwardingState} (iface : MACIface) (association : MacsecAssociation)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .egressReady)
      (logical : s.iface = iface.logicalIface)
      (enabled : iface.settings.controlledPortEnabled = true)
      (protection : iface.settings.protectFrames = true)
      (installed : iface.transmitAssociation = some association)
      (limited : iface.settings.encryptFrames = false ∨ iface.settings.confidentialityOffset ≠ 0) :
      TunnelForwardingStep c s .protectMACsec { s with initialEntry := false, iface := iface.physicalIface, frame := c.macsecPduFrame s.frame association iface.settings.encryptFrames iface.settings.confidentialityOffset }
  | decryptMACsec {s : TunnelForwardingState} (iface : MACIface) (association transmitted : MacsecAssociation) (body : Body)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .received)
      (physical : s.iface = iface.physicalIface)
      (encrypted : s.frame.body = .macsec transmitted body)
      (installed : association ∈ iface.receiveAssociations)
      (spi : SameMACWireIdentity transmitted association) :
      TunnelForwardingStep c s .decryptMACsec { s with initialEntry := false, iface := iface.logicalIface, frame := c.restoredFrame s.frame body, authenticated := [] }
  | validateMACsec {s : TunnelForwardingState} (iface : MACIface)
      (association transmitted : MacsecAssociation) (encryptFrames : Bool)
      (confidentialityOffset : Nat) (body : Body)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .received)
      (physical : s.iface = iface.physicalIface)
      (framed : s.frame.body = .macsecPdu transmitted encryptFrames confidentialityOffset body)
      (installed : association ∈ iface.receiveAssociations)
      (spi : SameMACWireIdentity transmitted association) :
      TunnelForwardingStep c s .validateMACsec { s with initialEntry := false, iface := iface.logicalIface, frame := c.restoredFrame s.frame body, authenticated := [] }
  | uncheckedMACsec {s : TunnelForwardingState} (iface : MACIface)
      (configured : iface ∈ c.macIfaces) (datapathStage : s.datapathStage = .received)
      (physical : s.iface = iface.physicalIface) (unchecked : iface.validateStrict = false) :
      TunnelForwardingStep c s .forwardWithoutEncap { s with initialEntry := false, iface := iface.logicalIface, authenticated := [] }
  | encapsulate {s : TunnelForwardingState} (iface : CarrierIface)
      (configured : iface ∈ c.carriers) (datapathStage : s.datapathStage = .egressReady)
      (virtualIface : s.iface = iface.virtualIface) :
      TunnelForwardingStep c s .encapsulate { s with initialEntry := false, iface := iface.routingIface, datapathStage := .localOutput, enteredIface := iface.routingIface, authenticated := [], frame := c.carrierFrame iface.routingIface s.frame iface.transmit }
  | decapsulate {s : TunnelForwardingState} (iface : CarrierIface) (body : Body)
      (configured : iface ∈ c.carriers) (datapathStage : s.datapathStage = .localInput)
      (owner : c.ip.owner s.iface = c.ip.owner iface.routingIface)
      (unwrapped : unwrapCarrier iface.transmit.source iface.transmit.destination
        iface.transmit.destinationPort iface.transmit.sourcePort iface.localSession s.frame.body iface.transmit.protocol iface.transmit.networkProtocol = some body) :
      TunnelForwardingStep c s .decapsulate { s with initialEntry := false, iface := iface.virtualIface, datapathStage := .received, frame := c.restoredFrame s.frame body, authenticated := [] }
  | drop (s : TunnelForwardingState) : TunnelForwardingStep c s .drop { s with initialEntry := false, datapathStage := .dropped }

def lts (c : TunnelForwardingModel) : Cslib.LTS TunnelForwardingState TunnelForwardingAction := ⟨TunnelForwardingStep c⟩

def ForwardsAlongTrace (net : TunnelForwardingModel) (startPkt : TunnelForwardingState)
    (actions : List TunnelForwardingAction) (endPkt : TunnelForwardingState) : Prop :=
  (lts net).MTr startPkt actions endPkt

lemma step_preserves_payload {c : TunnelForwardingModel} {before after : TunnelForwardingState} {action : TunnelForwardingAction}
    (step : TunnelForwardingStep c before action after) :
    after.frame.payload = before.frame.payload ∧
    after.frame.originDomain = before.frame.originDomain := by
  cases mode : c.headerProcessing <;> cases step <;>
    simp [TunnelForwardingModel.forwardedFrame, TunnelForwardingModel.ipsecFrame, TunnelForwardingModel.macsecFrame,
      TunnelForwardingModel.carrierFrame, TunnelForwardingModel.macsecPduFrame, TunnelForwardingModel.restoredFrame, mode, TunnelFrame.pushHeader, TunnelFrame.popHeader]

theorem all_traces_preserve_payload (c : TunnelForwardingModel)
    {before after : TunnelForwardingState} {actions : List TunnelForwardingAction}
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

def TunnelForwardingModel.LinkPath (c : TunnelForwardingModel) (iface : Nat) : Prop :=
  (∃ mac ∈ c.macIfaces, mac.physicalIface = iface) ∨
  (∃ next, c.bridge iface next ∨ c.bridge next iface) ∨
  ∃ carrier ∈ c.carriers, carrier.virtualIface = iface

def TunnelForwardingModel.LinkAdmitted (c : TunnelForwardingModel) (iface : Nat) (outbound : Bool)
    (frame : LayeredFrame.TunnelFrame) : Prop :=
  ∃ encoded, c.linkEncoding iface frame = some encoded ∧ encoded.Describes frame ∧
    LinkAdmission.Admitted c.linkPolicies iface outbound
      (encoded.Packet (if outbound then "" else c.ip.interfaceName iface)
        (if outbound then c.ip.interfaceName iface else ""))

def TunnelForwardingModel.LinkStepAdmitted (c : TunnelForwardingModel) (before : TunnelForwardingState) (action : TunnelForwardingAction) (after : TunnelForwardingState) : Prop :=
  (action = .linkTransmit →
    (c.LinkPath before.iface → c.LinkAdmitted before.iface true before.frame) ∧
    (c.LinkPath after.iface → c.LinkAdmitted after.iface false after.frame) ∧
    (c.LinkPath before.iface ∨ c.LinkPath after.iface →
      c.linkEncoding before.iface before.frame = c.linkEncoding after.iface after.frame)) ∧
  ((action = .decryptMACsec ∨ action = .validateMACsec) →
    c.LinkAdmitted before.iface false before.frame) ∧
  (action = .bridge →
    c.LinkAdmitted before.iface false before.frame ∧
    c.LinkAdmitted after.iface true after.frame) ∧
  (action = .deliver → before.frame.visibleHeader = none → c.LinkPath before.iface →
    c.LinkAdmitted before.iface false before.frame)

end TDN.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def TunnelForwardingModel.ForwardableHeader (c : TunnelForwardingModel) (header : PacketPolicy.Packet) : Prop :=
  c.headerProcessing.isSome = true → 1 < header.hopLimit

def TunnelForwardingModel.HeaderStepAdmitted (c : TunnelForwardingModel) (before : TunnelForwardingState) (action : TunnelForwardingAction) : Prop :=
  action = .route → before.datapathStage = .ingress →
    ∀ header, c.visibleHeader before.frame = some header → c.ForwardableHeader header

def TunnelForwardingModel.HeaderGenerationKnown (c : TunnelForwardingModel) (ifaces : List Nat) : Prop :=
  ∃ processing, c.headerProcessing = some processing ∧
    ∀ iface ∈ ifaces,
      0 < processing.ipsecHopLimit iface ∧ processing.ipsecHopLimit iface ≤ 255 ∧
      0 < processing.carrierHopLimit iface ∧ processing.carrierHopLimit iface ≤ 255

def TunnelForwardingModel.LinkEncodingComplete (c : TunnelForwardingModel) (state : TunnelForwardingState) : Prop :=
  c.LinkPath state.iface →
    ∃ encoded, c.linkEncoding state.iface state.frame = some encoded ∧
      encoded.Describes state.frame

end TDN.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

@[simp] lemma TunnelForwardingModel.forwarded_frame_body (c : TunnelForwardingModel) (frame : TunnelFrame) :
    (c.forwardedFrame frame).body = frame.body := by
  cases mode : c.headerProcessing <;> simp [TunnelForwardingModel.forwardedFrame, mode]

@[simp] lemma TunnelForwardingModel.ipsec_frame_body (c : TunnelForwardingModel) (iface : Nat) (frame : TunnelFrame)
    (association : DataPlaneForwarding.TunnelSaStamp) :
    (c.ipsecFrame iface frame association).body = .ipsec association frame.body := by
  unfold TunnelForwardingModel.ipsecFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma TunnelForwardingModel.macsec_frame_body (c : TunnelForwardingModel) (frame : TunnelFrame)
    (association : MacsecAssociation) :
    (c.macsecFrame frame association).body = .macsec association frame.body := by
  unfold TunnelForwardingModel.macsecFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma TunnelForwardingModel.macsec_pdu_frame_body (c : TunnelForwardingModel) (frame : TunnelFrame)
    (association : MacsecAssociation) (encryptFrames : Bool) (confidentialityOffset : Nat) :
    (c.macsecPduFrame frame association encryptFrames confidentialityOffset).body =
      .macsecPdu association encryptFrames confidentialityOffset frame.body := by
  unfold TunnelForwardingModel.macsecPduFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma TunnelForwardingModel.carrier_frame_body (c : TunnelForwardingModel) (iface : Nat) (frame : TunnelFrame)
    (endpoint : EthernetTunnelHeader) :
    (c.carrierFrame iface frame endpoint).body = .carrier endpoint frame.body := by
  unfold TunnelForwardingModel.carrierFrame
  cases c.headerProcessing <;> rfl

@[simp] lemma TunnelForwardingModel.restored_frame_body (c : TunnelForwardingModel) (frame : TunnelFrame) (body : Body) :
    (c.restoredFrame frame body).body = body := by
  unfold TunnelForwardingModel.restoredFrame
  cases c.headerProcessing <;> rfl

end TDN.MultiProtocolForwarding
