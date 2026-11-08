import TDN.Targets.Architecture
import TDN.Semantics.PacketPolicy
import TDN.Semantics.Waypointing
import TDN.Semantics.MultiProtocolExecution
import TDN.Semantics.PacketSource
import TDN.Semantics.PacketProcessing
import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.Compliance

inductive DeviceKind where
  | vpn | macsec | grayFirewall | outerFirewall | innerFirewall | encapsulator
  | workstation | certificationAuthority | revocationService | authenticationServer
  | keyGenerationSolution | siem | crossDomain | intrusionPrevention | screeningRouter
  | ordinaryGrayRouter | ordinaryGraySwitch | other
  deriving DecidableEq

structure Device where
  id : String
  site : String
  kind : DeviceKind
  layer : Option Layer
  level : SecurityLevel
  infrastructure : Bool

structure Interface where
  id : String
  device : String
  zone : Zone
  address : Option Nat
  namespaceAddresses : List Nat := []
  linkAddress : Option Nat := none
  physical : Bool
  externalData : Bool := false
  managementNetwork : Bool
  mtu : Option Nat := none

def Interface.HasLocalAddress (interface : Interface) (address : Nat) : Prop :=
  interface.address = some address ∨ address ∈ interface.namespaceAddresses

instance (interface : Interface) (address : Nat) : Decidable (interface.HasLocalAddress address) := by
  unfold Interface.HasLocalAddress
  infer_instance

inductive Direction where
  | inbound | outbound
  deriving DecidableEq

inductive TrafficClass where
  | protectedData | management | control
  deriving DecidableEq

structure Traffic where
  packet : PacketPolicy.Packet
  ipVersion : Option Nat
  ipProtocol : Nat
  multicast : Bool
  trafficClass : TrafficClass
  sourceDevice : Option String
  destinationDevice : Option String
  originator : String
  service : String
  innerRevocation : Bool
  remoteRequest : Bool

structure InterfacePolicy where
  interface : String
  direction : Direction
  rules : List PacketPolicy.Rule
  defaultVerdict : Filter.Verdict
  hook : PacketProcessing.Hook := .forward

def InterfacePolicy.Accepts (policy : InterfacePolicy) (traffic : Traffic) : Prop :=
  Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter) policy.defaultVerdict
    traffic.packet = .allow

structure Tunnel where
  id : String
  layer : Layer
  mechanism : Mechanism
  sender : String
  receiver : String
  keyContext : String
  espTunnelMode : Bool
  associatedIPTunnel : Bool

inductive PayloadOrigin where
  | red (network : String)
  | management (component : String)
  | control (component protocol : String)
  deriving DecidableEq

structure PayloadId where
  originDomain : Nat
  value : Nat
  deriving DecidableEq

def PayloadCode (bytes : List UInt8) : Nat :=
  bytes.foldl (fun accumulator byte => accumulator * 256 + byte.toNat) 1

inductive ProtectionSession where
  | ipsec (association : Execution.Seal)
  | macsec (association : LayeredFrame.MACsecAssociation)
  deriving DecidableEq

inductive NetworkEvent where
  | protect (payload : PayloadId) (tunnel : String) (session : ProtectionSession)
  | unprotect (payload : PayloadId) (tunnel : String) (session : ProtectionSession)
  | sessionTransmit (payload : PayloadId) (interface : String) (sessions : List ProtectionSession)
  | sessionReceive (payload : PayloadId) (interface : String) (sessions : List ProtectionSession)
  | useSAK (payload : PayloadId) (tunnel key : String)
  | inject (payload : PayloadId) (network : String)
  | encrypt (payload : PayloadId) (tunnel : String)
  | decrypt (payload : PayloadId) (tunnel : String)
  | encapsulate (payload : PayloadId) (component protocol : String)
  | decapsulate (payload : PayloadId) (component protocol : String)
  | transmit (payload : PayloadId) (interface : String) (layers : List String) (trafficClass : TrafficClass)
  | receive (payload : PayloadId) (interface : String) (layers : List String) (trafficClass : TrafficClass)
  | deliver (payload : PayloadId) (network : String) (layers : List String)
  | authenticate (verifier claimant credential : String)
  | eapTLSVerified (session device server deviceCertificate serverCertificate msk : String)
  | eapKeyDelivered (session server authenticator supplicant msk : String)
  | deriveCAK (session device msk cak : String)
  | issueSAK (server peer key : String)
  | historySend (session sender receiver : String) (message : List UInt8)
  | historyReceive (session sender receiver : String) (message : List UInt8)
  | installSAK (component key installation epoch : String)
  | privateKeyRead (component key principal : String)
  | privateKeyExport (component key interface : String)
  deriving DecidableEq

def MACsecKeyMaterialMatches
    (keyMaterial : LayeredFrame.MACsecAssociation → Option (List UInt8))
    (transmitted installed : LayeredFrame.MACsecAssociation) : Prop :=
  ∃ key, (key.length = 16 ∨ key.length = 32) ∧
    keyMaterial transmitted = some key ∧ keyMaterial installed = some key

inductive IPsecSADirection where
  | outbound | inbound
  deriving DecidableEq

structure IPsecLocalSA where
  device : Nat
  direction : IPsecSADirection
  association : Execution.SecurityAssociation
  epoch : String
  installation : String
  deriving DecidableEq

structure IPsecTransform where
  encryptionAlgorithm : String
  encryptionKeyBits : Nat
  saltBytes : Nat
  integrityAlgorithm : Option String
  integrityKeyBits : Nat
  authenticationBits : Nat
  deriving DecidableEq

structure IPsecKeyMaterial where
  transform : IPsecTransform
  encryptionKey : List UInt8
  salt : List UInt8
  integrityKey : List UInt8
  deriving DecidableEq

def IPsecKeyMaterial.Valid (material : IPsecKeyMaterial) : Prop :=
  material.transform.encryptionAlgorithm ≠ "" ∧
  0 < material.transform.encryptionKeyBits ∧
  material.encryptionKey.length * 8 = material.transform.encryptionKeyBits ∧
  material.salt.length = material.transform.saltBytes ∧
  0 < material.transform.authenticationBits ∧
  match material.transform.integrityAlgorithm with
  | none => material.integrityKey = [] ∧ material.transform.integrityKeyBits = 0
  | some algorithm => algorithm ≠ "" ∧ 0 < material.transform.integrityKeyBits ∧
      material.integrityKey.length * 8 = material.transform.integrityKeyBits

def IPsecKeyMaterialMatches (keyMaterial : IPsecLocalSA → Option IPsecKeyMaterial)
    (source receiver : IPsecLocalSA) : Prop :=
  ∃ material, material.Valid ∧
    keyMaterial source = some material ∧ keyMaterial receiver = some material

structure NativeExecutionBinding (State Action : Type) where
  configuration : MultiProtocolExecution.Config
  state : State → MultiProtocolExecution.State
  action : Action → Option MultiProtocolExecution.Action
  ifaceName : Nat → String
  ipsecTunnel : Execution.Seal → String
  ipsecEpoch : Option String
  ipsecInstallations : List IPsecLocalSA
  ipsecKeyMaterial : IPsecLocalSA → Option IPsecKeyMaterial
  macsecEpoch : Option String := none
  macsecTunnel : LayeredFrame.MACsecAssociation → String
  macsecKeyMaterial : LayeredFrame.MACsecAssociation → Option (List UInt8)
  componentName : Nat → String
  sourceEntry : Nat → Option String
  sourceProcessing : PacketSource.Processing
  keyName : Nat → String
  domainName : Nat → String
  origin : Nat → PayloadOrigin

structure HistoricalEvent where
  source : String
  observer : String
  localPosition : Nat
  component : String
  position : Nat
  epoch : String
  session : Option String
  event : NetworkEvent
  deriving DecidableEq

def HistoricalEvent.SetupOnly (record : HistoricalEvent) : Prop :=
  match record.event with
  | .eapTLSVerified session .. | .eapKeyDelivered session .. | .deriveCAK session .. =>
      record.session = some session
  | .historySend session _ _ message | .historyReceive session _ _ message =>
      record.session = some session ∧ message ≠ []
  | .installSAK _ _ _ epoch => record.epoch = epoch
  | .authenticate .. | .issueSAK .. => True
  | _ => False

structure ObservedHistory where
  stream : String := ""
  epoch : String := ""
  cut : Nat := 0
  entries : List HistoricalEvent := []
  dependencies : List (Nat × Nat) := []

def ObservedHistory.Events (history : ObservedHistory) : List NetworkEvent :=
  history.entries.map HistoricalEvent.event

def HistoricalEvent.DirectPrecedes (first second : HistoricalEvent) : Prop :=
  (first.observer = second.observer ∧ first.component = second.component ∧
    first.localPosition < second.localPosition) ∨
  ∃ session sender receiver message,
    message ≠ [] ∧ first.component = sender ∧ second.component = receiver ∧
    first.epoch = second.epoch ∧
    first.event = .historySend session sender receiver message ∧
    second.event = .historyReceive session sender receiver message

def ObservedHistory.DependencyValid (history : ObservedHistory) (edge : Nat × Nat) : Prop :=
  ∃ first ∈ history.entries, ∃ second ∈ history.entries,
    first.position = edge.1 ∧ second.position = edge.2 ∧ first.DirectPrecedes second

def ObservedHistory.CausallyBefore (history : ObservedHistory) (first second : Nat) : Prop :=
  first < second ∧ Relation.ReflTransGen
    (fun earlier later => (earlier, later) ∈ history.dependencies) first second

def ObservedHistory.Valid (history : ObservedHistory) : Prop :=
  (history.entries ≠ [] → history.stream ≠ "" ∧ history.epoch ≠ "") ∧
  (∀ record ∈ history.entries,
    record.source ≠ "" ∧ record.observer ≠ "" ∧ record.epoch = history.epoch ∧
    record.position < history.cut ∧ record.SetupOnly) ∧
  history.entries.Pairwise (fun first second => first.position < second.position) ∧
  (∀ edge ∈ history.dependencies, edge.1 < edge.2 ∧ history.DependencyValid edge)

structure MACsecHistoryInstallation where
  device : Nat
  association : LayeredFrame.MACsecAssociation
  epoch : String
  installation : String
  source : String
  installedAt : Nat
  issuedAt : Nat
  issuer : String
  peer : String
  session : Option String
  keyReference : String
  deriving DecidableEq

structure ExecutionModel (State Action : Type) where
  system : Cslib.LTS State Action
  initial : State → Prop
  events : Action → List NetworkEvent
  native : NativeExecutionBinding State Action
  sourceRecord : State → Option (PacketSource.Request × PacketSource.Datagram) := fun _ => none
  history : ObservedHistory := {}
  macsecInstallationHistory : List MACsecHistoryInstallation := []
  historicalKeyMaterial : String → Option (List UInt8) := fun _ => none

def NativeExecutionBinding.LayerIds {S A : Type} (binding : NativeExecutionBinding S A) :
    LayeredFrame.Body → List String
  | .datagram _ | .ethernet _ => []
  | .ipsec authentication body => binding.ipsecTunnel authentication :: binding.LayerIds body
  | .macsec association body => binding.macsecTunnel association :: binding.LayerIds body
  | .carrier _ body => binding.LayerIds body

def NativeExecutionBinding.SessionTunnel {S A : Type} (binding : NativeExecutionBinding S A) :
    ProtectionSession → String
  | .ipsec authentication => binding.ipsecTunnel authentication
  | .macsec association => binding.macsecTunnel association

def BodySessions : LayeredFrame.Body → List ProtectionSession
  | .datagram _ | .ethernet _ => []
  | .ipsec authentication body => .ipsec authentication :: BodySessions body
  | .macsec association body => .macsec association :: BodySessions body
  | .carrier _ body => BodySessions body

def NativeExecutionBinding.OperationEvents {S A : Type} (binding : NativeExecutionBinding S A)
    (before : S) (action : MultiProtocolExecution.Action) (after : S) : List NetworkEvent :=
  let first := binding.state before
  let last := binding.state after
  let payload : PayloadId := ⟨first.frame.originDomain, first.frame.payload⟩
  let trafficClass := match binding.origin first.frame.originDomain with
    | .red _ => TrafficClass.protectedData
    | .management _ => .management
    | .control _ _ => .control
  let oldLayers := binding.LayerIds first.frame.body
  let newLayers := binding.LayerIds last.frame.body
  match action with
  | .encryptIPsec =>
      match last.frame.body with
      | .ipsec authentication _ =>
          [.protect payload (binding.ipsecTunnel authentication) (.ipsec authentication),
            .encrypt payload (binding.ipsecTunnel authentication)]
      | _ => []
  | .encryptMACsec =>
      match last.frame.body with
      | .macsec association _ =>
          [.useSAK payload (binding.macsecTunnel association) (binding.keyName association.keyGeneration),
            .protect payload (binding.macsecTunnel association) (.macsec association),
            .encrypt payload (binding.macsecTunnel association)]
      | _ => []
  | .decryptIPsec =>
      match first.frame.body with
      | .ipsec authentication _ =>
          [.unprotect payload (binding.ipsecTunnel authentication) (.ipsec authentication),
            .decrypt payload (binding.ipsecTunnel authentication)]
      | _ => []
  | .decryptMACsec =>
      match first.frame.body with
      | .macsec association _ =>
          [.unprotect payload (binding.macsecTunnel association) (.macsec association),
            .decrypt payload (binding.macsecTunnel association)]
      | _ => []
  | .linkTransmit =>
      [.sessionTransmit payload (binding.ifaceName first.iface) (BodySessions first.frame.body),
        .transmit payload (binding.ifaceName first.iface) oldLayers trafficClass,
        .receive payload (binding.ifaceName last.iface) newLayers trafficClass,
        .sessionReceive payload (binding.ifaceName last.iface) (BodySessions last.frame.body)]
  | .receive => []
  | .encapsulate =>
      match last.frame.body with
      | .carrier carrier _ =>
          [.encapsulate payload (binding.componentName (binding.configuration.ip.owner first.iface))
            carrier.protocol]
      | _ => []
  | .decapsulate =>
      match first.frame.body with
      | .carrier carrier _ =>
          [.decapsulate payload (binding.componentName (binding.configuration.ip.owner last.iface))
            carrier.protocol]
      | _ => []
  | .deliver =>
      match binding.configuration.ip.recipientDomain first.iface with
      | some domain => [.deliver payload (binding.domainName domain) newLayers]
      | none => []
  | _ => []

def NativeExecutionBinding.SourceEvents {S A : Type} (binding : NativeExecutionBinding S A)
    (before : S) : List NetworkEvent :=
  let state := binding.state before
  let payload : PayloadId := ⟨state.frame.originDomain, state.frame.payload⟩
  if state.initialEntry then
    match binding.origin state.frame.originDomain with
    | .red network =>
        if binding.sourceEntry state.iface = some network ∧ binding.LayerIds state.frame.body = []
        then [.inject payload network,
          .receive payload (binding.ifaceName state.iface) [] .protectedData]
        else []
    | _ => []
  else []

def NativeExecutionBinding.RequiredEvents {S A : Type} (binding : NativeExecutionBinding S A)
    (before : S) (action : MultiProtocolExecution.Action) (after : S) : List NetworkEvent :=
  binding.SourceEvents before ++ binding.OperationEvents before action after

def NetworkEvent.NetworkOperation : NetworkEvent → Bool
  | .protect .. | .unprotect .. | .sessionTransmit .. | .sessionReceive .. | .useSAK .. |
    .inject .. | .encrypt .. | .decrypt .. | .encapsulate .. | .decapsulate .. |
      .transmit .. | .receive .. | .deliver .. => true
  | _ => false

def NativeExecutionBinding.MACsecKeyInventory {S A : Type}
    (binding : NativeExecutionBinding S A) : Prop :=
  ∀ iface ∈ binding.configuration.macIfaces, ∀ association,
    (iface.transmitAssociation = some association ∨ association ∈ iface.receiveAssociations) →
    ∃ key, binding.macsecKeyMaterial association = some key ∧
      (key.length = 16 ∨ key.length = 32)

def IPsecLocalSA.InstalledAt {S A : Type} (installation : IPsecLocalSA)
    (binding : NativeExecutionBinding S A) (iface : Nat) : Prop :=
  installation.device = binding.configuration.ip.owner iface ∧
  match installation.direction with
  | .outbound => installation.association ∈ binding.configuration.ip.outboundStates iface
  | .inbound => installation.association ∈ binding.configuration.ip.inboundStates iface

def IPsecLocalSA.OutboundSeal {S A : Type} (installation : IPsecLocalSA)
    (binding : NativeExecutionBinding S A) (wireSeal : Execution.Seal) : Prop :=
  installation.direction = .outbound ∧
  ∃ iface, installation.InstalledAt binding iface ∧
    ∃ policy ∈ binding.configuration.ip.outbound iface,
      Execution.StateBindsPolicy installation.association policy ∧
      policy.seal installation.association = wireSeal

def IPsecLocalSA.InboundSeal {S A : Type} (installation : IPsecLocalSA)
    (binding : NativeExecutionBinding S A) (iface : Nat) (wireSeal : Execution.Seal) : Prop :=
  installation.direction = .inbound ∧ installation.InstalledAt binding iface ∧
  ∃ policy ∈ binding.configuration.ip.inbound iface,
    Execution.StateBindsPolicy installation.association policy ∧
    policy.seal installation.association = wireSeal

def NativeExecutionBinding.IPsecKeyInventory {S A : Type}
    (binding : NativeExecutionBinding S A) : Prop :=
  (∀ installation ∈ binding.ipsecInstallations, ∃ epoch,
    binding.ipsecEpoch = some epoch ∧ installation.epoch = epoch ∧
    installation.installation ≠ "" ∧
    (∃ iface, installation.InstalledAt binding iface) ∧
    ∃ material, binding.ipsecKeyMaterial installation = some material ∧ material.Valid) ∧
  (∀ iface association, association ∈ binding.configuration.ip.outboundStates iface →
    ∃ installation ∈ binding.ipsecInstallations,
      installation.device = binding.configuration.ip.owner iface ∧
      installation.direction = .outbound ∧ installation.association = association) ∧
  (∀ iface association, association ∈ binding.configuration.ip.inboundStates iface →
    ∃ installation ∈ binding.ipsecInstallations,
      installation.device = binding.configuration.ip.owner iface ∧
      installation.direction = .inbound ∧ installation.association = association) ∧
  (∀ first ∈ binding.ipsecInstallations, ∀ second ∈ binding.ipsecInstallations,
    first.device = second.device → first.installation = second.installation → first = second) ∧
  (∀ first ∈ binding.ipsecInstallations, ∀ second ∈ binding.ipsecInstallations, ∀ wireSeal,
    first.OutboundSeal binding wireSeal → second.OutboundSeal binding wireSeal → first = second) ∧
  (∀ first ∈ binding.ipsecInstallations, ∀ second ∈ binding.ipsecInstallations, ∀ iface wireSeal,
    first.InboundSeal binding iface wireSeal → second.InboundSeal binding iface wireSeal → first = second)

def NativeExecutionBinding.AcceptedStep {S A : Type} (binding : NativeExecutionBinding S A)
    (before : MultiProtocolExecution.State) (action : MultiProtocolExecution.Action)
    (after : MultiProtocolExecution.State) : Prop :=
  MultiProtocolExecution.Step binding.configuration before action after ∧
  (action = .decryptMACsec →
    ∃ iface ∈ binding.configuration.macIfaces, ∃ installed ∈ iface.receiveAssociations,
      ∃ transmitted body,
        before.iface = iface.physicalIface ∧ after.iface = iface.logicalIface ∧
        before.frame.body = .macsec transmitted body ∧ after.frame.body = body ∧
        LayeredFrame.SameMACWireIdentity transmitted installed ∧
        MACsecKeyMaterialMatches binding.macsecKeyMaterial transmitted installed) ∧
  (action = .decryptIPsec →
    ∃ source ∈ binding.ipsecInstallations, ∃ receiver ∈ binding.ipsecInstallations,
      ∃ wireSeal body, before.frame.body = .ipsec wireSeal body ∧ after.frame.body = body ∧
        source.OutboundSeal binding wireSeal ∧
        receiver.InboundSeal binding before.iface wireSeal ∧
        IPsecKeyMaterialMatches binding.ipsecKeyMaterial source receiver) ∧
  binding.configuration.LinkStepAdmitted before action after ∧
  binding.configuration.HeaderStepAdmitted before action

def ExecutionModel.Faithful {S A : Type} (model : ExecutionModel S A) : Prop :=
  ∀ before action after, model.system.Tr before action after →
    match model.native.action action with
    | some nativeAction =>
        model.native.AcceptedStep
          (model.native.state before) nativeAction (model.native.state after) ∧
        (model.events action).filter NetworkEvent.NetworkOperation =
          model.native.RequiredEvents before nativeAction after
    | none =>
        model.native.state before = model.native.state after ∧
        (model.events action).filter NetworkEvent.NetworkOperation = []

def ExecutionModel.NativeStepCoverage {S A : Type} (model : ExecutionModel S A) : Prop :=
  ∀ before nativeAction nativeAfter,
    model.native.AcceptedStep
      (model.native.state before) nativeAction nativeAfter →
    ∃ action after, model.system.Tr before action after ∧
      model.native.action action = some nativeAction ∧ model.native.state after = nativeAfter

def ExecutionModel.TraceEvents {S A : Type} (model : ExecutionModel S A)
    (actions : List A) : List NetworkEvent :=
  model.history.Events ++ actions.flatMap model.events

def MACsecHistoryInstallation.Bound {S A : Type} (record : MACsecHistoryInstallation)
    (model : ExecutionModel S A) : Prop :=
  model.native.macsecEpoch = some record.epoch ∧
  record.epoch = model.history.epoch ∧ record.installation ≠ "" ∧ record.source ≠ "" ∧
  record.keyReference ≠ "" ∧
  model.native.keyName record.association.keyGeneration = record.keyReference ∧
  model.history.CausallyBefore record.issuedAt record.installedAt ∧
  record.installedAt < model.history.cut ∧
  (∃ observation ∈ model.history.entries,
    observation.position = record.installedAt ∧ observation.epoch = record.epoch ∧
    observation.session = record.session ∧
    observation.event = .installSAK (model.native.componentName record.device)
      record.keyReference record.installation record.epoch) ∧
  (∃ observation ∈ model.history.entries,
    observation.position = record.issuedAt ∧ observation.epoch = record.epoch ∧
    observation.session = record.session ∧
    observation.event = .issueSAK record.issuer record.peer record.keyReference) ∧
  ∃ material, (material.length = 16 ∨ material.length = 32) ∧
    model.historicalKeyMaterial record.keyReference = some material ∧
    model.native.macsecKeyMaterial record.association = some material

def ExecutionModel.AllTraces {S A : Type} (model : ExecutionModel S A)
    (property : List NetworkEvent → Prop) : Prop :=
  ∀ start actions finish, model.initial start → model.system.MTr start actions finish →
    property (model.TraceEvents actions)

def Before (events : List NetworkEvent) (first second : NetworkEvent) : Prop :=
  ∃ earlier middle later, events = earlier ++ [first] ++ middle ++ [second] ++ later

def BeforeEvery (events : List NetworkEvent) (first second : NetworkEvent) : Prop :=
  ∀ earlier later, events = earlier ++ [second] ++ later → first ∈ earlier

structure AuthorityFacts where
  nsaApprovedGenerator : String → Prop
  aoApprovedEncapsulation : String → Prop
  aoApprovedTransitSolution : String → Prop
  protectsAsClassified : String → Prop
  certificateCNSACompliant : String → Prop
  authenticationConformsToNIST80063 : String → Prop
  securityAdministrator : String → Prop

inductive ServiceKind where
  | logging | authentication | administration | time | control | application
  deriving DecidableEq

structure ServiceRegistration where
  device : String
  protocol : String
  port : Nat
  kind : ServiceKind
  deriving DecidableEq

def ServiceKind.name : ServiceKind → String
  | .logging => "logging"
  | .authentication => "authentication"
  | .administration => "administration"
  | .time => "time"
  | .control => "control"
  | .application => "application"

structure ManagementPacketObservation where
  observer : String
  order : Nat
  sourceComponent : String
  sourceInterface : String
  packet : PacketPolicy.Packet
  rawReference : String
  deriving DecidableEq

structure ManagementExchange where
  id : String
  responder : String
  request : ManagementPacketObservation
  established : ManagementPacketObservation
  deriving DecidableEq

inductive ManagementServiceFunction where
  | administration | certification | revocation | authentication | keyGeneration | monitoring
  | timeSynchronization | nameResolution | other (service : String)
  deriving DecidableEq

inductive ManagementDomain where
  | red | gray
  deriving DecidableEq

def ManagementDomain.zone : ManagementDomain → Zone
  | .red => .red
  | .gray => .gray

structure ManagementServiceInstance where
  id : String
  device : String
  function : ManagementServiceFunction
  domain : ManagementDomain
  interface : String
  process : String
  deriving DecidableEq

structure RedNetworkAttachment where
  network : String
  interface : String
  deriving DecidableEq

structure Deployment where
  processing : Option PacketProcessing.Inventory := none
  udpBindings : List PacketProcessing.UDPBinding := []
  grayManagementTunnels : List String := []
  carrierBindings : List PacketProcessing.CarrierBinding := []
  dropIPv4Options : String → Bool := fun _ => false
  focus : Option String := none
  services : List ServiceRegistration := []
  managementServices : List ManagementServiceInstance := []
  managementHistory : List ManagementPacketObservation := []
  managementExchanges : List ManagementExchange := []
  devices : List Device
  interfaces : List Interface
  tunnels : List Tunnel
  networks : List RedNetworkIdentity
  redNetworkAttachments : List RedNetworkAttachment := []
  centralManagementSite : Option String
  networkAttachment : String → String → Zone → Prop
  policies : List InterfacePolicy
  physicalLink : String → String → Prop
  storedVPNKey : String → String → Prop
  certificateAuthenticated : String → Bool
  preSharedCAKAuthenticated : String → Bool
  keyManagementCA : String → String → Prop
  keyManagementGenerator : String → String → Prop
  innerUsesOuter : String → String → Prop
  intendedPeer : String → String → Prop
  policyApproved : String → Traffic → Prop
  aoApproved : String → Traffic → Prop
  reachableSource : String → Nat → Prop
  redService : String → Nat → Nat → Prop
  grayManagementService : String → Traffic → Prop
  grayWorkstation : String → Prop
  standaloneEncapsulator : String → Prop
  authority : AuthorityFacts

def Deployment.InterfaceLinksWellFormed (d : Deployment) : Prop :=
  ∀ first second, d.physicalLink first second →
    (∃ interface ∈ d.interfaces, interface.id = first) ∧
    (∃ interface ∈ d.interfaces, interface.id = second)

def Deployment.DeviceAdjacent (d : Deployment) (first second : String) : Prop :=
  ∃ source ∈ d.interfaces, ∃ destination ∈ d.interfaces,
    source.device = first ∧ destination.device = second ∧
    d.physicalLink source.id destination.id

def Deployment.RedAttachmentsWellFormed (d : Deployment) : Prop :=
  (∀ attachment ∈ d.redNetworkAttachments,
    (∃ network ∈ d.networks, network.id = attachment.network) ∧
    ∃ interface ∈ d.interfaces, interface.id = attachment.interface ∧
      interface.zone = .red ∧ interface.managementNetwork = false ∧
      ∃ device ∈ d.devices, device.id = interface.device) ∧
  (∀ first ∈ d.redNetworkAttachments, ∀ second ∈ d.redNetworkAttachments,
    first.interface = second.interface → first.network = second.network)

def Deployment.RedAttachmentDevice (d : Deployment) (network component : String) : Prop :=
  ∃ attachment ∈ d.redNetworkAttachments, attachment.network = network ∧
    ∃ interface ∈ d.interfaces, interface.id = attachment.interface ∧
      interface.device = component

def Deployment.OwnedGrayAttachment (d : Deployment)
    (first second : String) (secondIface : String) : Prop :=
  ∃ source ∈ d.interfaces, ∃ destination ∈ d.interfaces,
    source.device = first ∧ source.zone = .gray ∧
    destination.device = second ∧ destination.zone = .gray ∧
    destination.id = secondIface ∧ d.physicalLink source.id destination.id

def Deployment.OwnedGrayExit (d : Deployment)
    (first : String) (firstIface : String) (second : String) : Prop :=
  ∃ source ∈ d.interfaces, ∃ destination ∈ d.interfaces,
    source.device = first ∧ source.zone = .gray ∧ source.id = firstIface ∧
    destination.device = second ∧ destination.zone = .gray ∧
    d.physicalLink source.id destination.id

def Deployment.Relevant (d : Deployment) (component : String) : Prop :=
  d.focus = none ∨ d.focus = some component

def Deployment.RelevantKey (d : Deployment) (key : String) : Prop :=
  d.focus = none ∨ ∃ tunnel ∈ d.tunnels, tunnel.keyContext = key ∧
    (d.Relevant tunnel.sender ∨ d.Relevant tunnel.receiver)

def Deployment.IsDevice (d : Deployment) (id : String) (kind : DeviceKind) : Prop :=
  ∃ device ∈ d.devices, device.id = id ∧ device.kind = kind

def Deployment.IsLayer (d : Deployment) (id : String) (layer : Layer) : Prop :=
  ∃ device ∈ d.devices, device.id = id ∧ device.layer = some layer

def Deployment.OrdinaryGray (d : Deployment) (component : String) : Prop :=
  (∃ device ∈ d.devices, device.id = component ∧ device.layer = none ∧
    device.infrastructure = false ∧
    device.kind ∈ [.ordinaryGrayRouter, .ordinaryGraySwitch]) ∧
  (∃ interface ∈ d.interfaces, interface.device = component ∧ interface.zone = .gray) ∧
  ∀ interface ∈ d.interfaces, interface.device = component →
    interface.zone = .gray ∨ interface.zone = .local

def Interface.PacketAddress (interface : Interface) (packet : PacketPolicy.Packet) : Option Nat :=
  if packet.protocol = "ethernet" ∧ packet.etherType.isSome = true
    then interface.linkAddress else interface.address

def Deployment.IPSameLevelInner (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source ∈ d.devices, ∃ destination ∈ d.devices,
    source.layer = some .inner ∧ destination.layer = some .inner ∧
    source.level = destination.level ∧ d.intendedPeer source.id destination.id ∧
    traffic.sourceDevice = some source.id ∧ traffic.destinationDevice = some destination.id ∧
    (∃ interface ∈ d.interfaces, interface.device = source.id ∧ interface.zone = .gray ∧
      interface.PacketAddress traffic.packet = some traffic.packet.source) ∧
    ∃ interface ∈ d.interfaces, interface.device = destination.id ∧ interface.zone = .gray ∧
      interface.PacketAddress traffic.packet = some traffic.packet.destination

def PacketIsEthernet (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = "ethernet" ∧ packet.etherType.isSome = true

def PacketIKEHeader (bytes : List UInt8) : Prop :=
  PacketPolicy.IKEHeader bytes

def PacketIKE (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = "udp" ∧
  ((packet.sourcePort = 500 ∨ packet.destinationPort = 500) ∧ PacketIKEHeader (packet.payloadBytes.getD []) ∨
    (packet.sourcePort = 4500 ∨ packet.destinationPort = 4500) ∧
      (packet.payloadBytes.getD []).take 4 = [0, 0, 0, 0] ∧ PacketIKEHeader ((packet.payloadBytes.getD []).drop 4))

def PacketUDPESP (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = "udp" ∧ (packet.sourcePort = 4500 ∨ packet.destinationPort = 4500) ∧
  8 ≤ (packet.payloadBytes.getD []).length ∧ (packet.payloadBytes.getD []).take 4 ≠ [0, 0, 0, 0]

def PacketMKA (packet : PacketPolicy.Packet) : Prop :=
  PacketIsEthernet packet ∧ packet.etherType = some 34958 ∧
  4 ≤ (packet.payloadBytes.getD []).length ∧ (packet.payloadBytes.getD [])[1]? = some 5 ∧
  ((packet.payloadBytes.getD [])[2]?.getD 0).toNat * 256 + ((packet.payloadBytes.getD [])[3]?.getD 0).toNat =
    (packet.payloadBytes.getD []).length - 4

def PacketMACsec (packet : PacketPolicy.Packet) : Prop :=
  PacketIsEthernet packet ∧ packet.etherType = some 35045

def IPsecProtocol (traffic : Traffic) : Prop :=
  traffic.packet.protocol = "esp" ∨ PacketIKE traffic.packet ∨ PacketUDPESP traffic.packet

def TunnelProtocol (traffic : Traffic) : Prop :=
  IPsecProtocol traffic ∨ PacketMKA traffic.packet ∨ PacketMACsec traffic.packet

instance (packet : PacketPolicy.Packet) : Decidable (PacketIsEthernet packet) := by
  unfold PacketIsEthernet
  infer_instance

instance (bytes : List UInt8) : Decidable (PacketIKEHeader bytes) := by
  unfold PacketIKEHeader
  infer_instance

instance (packet : PacketPolicy.Packet) : Decidable (PacketIKE packet) := by
  unfold PacketIKE
  infer_instance

instance (packet : PacketPolicy.Packet) : Decidable (PacketUDPESP packet) := by
  unfold PacketUDPESP
  infer_instance

instance (packet : PacketPolicy.Packet) : Decidable (PacketMKA packet) := by
  unfold PacketMKA
  infer_instance

instance (packet : PacketPolicy.Packet) : Decidable (PacketMACsec packet) := by
  unfold PacketMACsec
  infer_instance

def PacketIPVersion (packet : PacketPolicy.Packet) : Option Nat :=
  if packet.protocol ∈ ["macsec", "mka", "arp", "ethernet"] then none
  else if packet.source < 2^32 ∧ packet.destination < 2^32 then some 4
  else if 2^128 ≤ packet.source ∧ packet.source < 2^129 ∧
    2^128 ≤ packet.destination ∧ packet.destination < 2^129 then some 6
  else none

def PacketIPProtocol (packet : PacketPolicy.Packet) : Nat :=
  if PacketIPVersion packet = some 6 then packet.ipv6NextHeader else
    match packet.protocol with
    | "tcp" => 6
    | "udp" => 17
    | "esp" => 50
    | "ospf" => 89
    | "icmp" => 1
    | other => other.toNat?.getD 0

def PacketMulticast (packet : PacketPolicy.Packet) : Bool :=
  match PacketIPVersion packet with
  | some 4 => decide (224 * 2^24 ≤ packet.destination ∧ packet.destination < 240 * 2^24)
  | some 6 => decide (255 * 2^120 ≤ packet.destination - 2^128)
  | _ => decide (packet.destination / 2^40 % 2 = 1)

def PacketPortService (packet : PacketPolicy.Packet) : String :=
  if packet.protocol = "tcp" ∧ (packet.sourcePort = 80 ∨ packet.destinationPort = 80) then "http"
  else if packet.protocol = "udp" ∧
    (packet.destinationPort = 514 ∨ packet.sourcePort = 514) then "logging"
  else if packet.protocol = "tcp" ∧ (packet.sourcePort ∈ [514, 601, 6514] ∨
    packet.destinationPort ∈ [514, 601, 6514]) then "logging"
  else if packet.protocol = "udp" ∧
    (packet.destinationPort ∈ [1812, 1813] ∨ packet.sourcePort ∈ [1812, 1813]) then "authentication"
  else if packet.protocol = "tcp" ∧
    (packet.destinationPort ∈ [22, 443] ∨ packet.sourcePort ∈ [22, 443]) then "administration"
  else if packet.protocol = "udp" ∧
    (packet.destinationPort = 123 ∨ packet.sourcePort = 123) then "time"
  else if packet.protocol ∈ ["udp", "tcp"] ∧
    (packet.destinationPort = 53 ∨ packet.sourcePort = 53) then "dns"
  else if packet.protocol = "udp" ∧
    (packet.destinationPort ∈ [67, 68] ∨ packet.sourcePort ∈ [67, 68]) then "dhcp"
  else packet.protocol

def PacketService (packet : PacketPolicy.Packet) : String :=
  if PacketIKE packet then "ike"
  else if PacketUDPESP packet then "esp"
  else PacketPortService packet

def PacketARP (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = "arp" ∨ (PacketIsEthernet packet ∧ packet.etherType = some 2054)

instance (packet : PacketPolicy.Packet) : Decidable (PacketARP packet) := by
  unfold PacketARP
  infer_instance

def Deployment.UDPModePacket (d : Deployment) (mode : PacketProcessing.UDPMode)
    (packet : PacketPolicy.Packet) : Prop :=
  ∃ binding ∈ d.udpBindings, binding.mode = mode ∧ binding.WellFormed ∧ binding.Framing packet

def Deployment.NATKeepalive (d : Deployment) (packet : PacketPolicy.Packet) : Prop :=
  d.UDPModePacket .keepalive packet

def Deployment.ConfiguredUDPProtocol (d : Deployment) (packet : PacketPolicy.Packet) : Prop :=
  d.UDPModePacket .ike packet ∨ d.UDPModePacket .ikeNATT packet ∨
    d.UDPModePacket .espNATT packet


def PacketClass (packet : PacketPolicy.Packet) : TrafficClass :=
  if PacketService packet ∈ ["logging", "authentication", "administration"]
    then .management
  else if PacketService packet ∈ ["time", "dns", "dhcp"] ∨ PacketIKE packet ∨ PacketMKA packet ∨ PacketARP packet ∨
    packet.protocol ∈ ["icmp", "icmpv6", "ndp", "ospf"] then .control
  else .protectedData

def Deployment.AddressOwner (d : Deployment) (address : Nat) : Option String :=
  (d.interfaces.find? (fun interface => interface.address == some address)).map Interface.device

def Deployment.PacketOwner (d : Deployment) (packet : PacketPolicy.Packet)
    (address : Nat) : Option String :=
  (d.interfaces.find? (fun interface =>
    interface.PacketAddress packet == some address)).map Interface.device

def ManagementPacketObservation.SourceBound (observation : ManagementPacketObservation)
    (d : Deployment) : Prop :=
  observation.rawReference ≠ "" ∧
  ∃ interface ∈ d.interfaces,
    interface.id = observation.sourceInterface ∧
    interface.device = observation.sourceComponent ∧
    interface.managementNetwork = true ∧
    interface.PacketAddress observation.packet = some observation.packet.source

def ManagementExchange.OriginalTuple (exchange : ManagementExchange)
    (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = exchange.request.packet.protocol ∧
  packet.source = exchange.request.packet.source ∧
  packet.destination = exchange.request.packet.destination ∧
  packet.sourcePort = exchange.request.packet.sourcePort ∧
  packet.destinationPort = exchange.request.packet.destinationPort

def ManagementExchange.ReverseTuple (exchange : ManagementExchange)
    (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = exchange.request.packet.protocol ∧
  packet.source = exchange.request.packet.destination ∧
  packet.destination = exchange.request.packet.source ∧
  packet.sourcePort = exchange.request.packet.destinationPort ∧
  packet.destinationPort = exchange.request.packet.sourcePort

def ManagementExchange.Valid (exchange : ManagementExchange) (d : Deployment) : Prop :=
  exchange.id ≠ "" ∧
  exchange.request ∈ d.managementHistory ∧ exchange.established ∈ d.managementHistory ∧
  exchange.request.SourceBound d ∧ exchange.established.SourceBound d ∧
  exchange.request.observer = exchange.established.observer ∧
  exchange.request.order < exchange.established.order ∧
  exchange.request.packet.connectionId = some exchange.id ∧
  exchange.established.packet.connectionId = some exchange.id ∧
  exchange.request.packet.connectionState = "new" ∧
  exchange.established.packet.connectionState = "established" ∧
  PacketClass exchange.request.packet = .management ∧
  d.PacketOwner exchange.request.packet exchange.request.packet.destination = some exchange.responder ∧
  exchange.established.sourceComponent = exchange.responder ∧
  exchange.ReverseTuple exchange.established.packet

def ManagementExchange.Matches (exchange : ManagementExchange) (packet : PacketPolicy.Packet) : Prop :=
  packet.connectionId = some exchange.id ∧
  ((exchange.OriginalTuple packet ∧ packet.connectionState ∈ ["new", "established"]) ∨
    (exchange.ReverseTuple packet ∧ packet.connectionState = "established"))

instance (observation : ManagementPacketObservation) (d : Deployment) :
    Decidable (observation.SourceBound d) := by
  unfold ManagementPacketObservation.SourceBound
  infer_instance

instance (exchange : ManagementExchange) (packet : PacketPolicy.Packet) :
    Decidable (exchange.OriginalTuple packet) := by
  unfold ManagementExchange.OriginalTuple
  infer_instance

instance (exchange : ManagementExchange) (packet : PacketPolicy.Packet) :
    Decidable (exchange.ReverseTuple packet) := by
  unfold ManagementExchange.ReverseTuple
  infer_instance

instance (exchange : ManagementExchange) (d : Deployment) :
    Decidable (exchange.Valid d) := by
  unfold ManagementExchange.Valid
  infer_instance

instance (exchange : ManagementExchange) (packet : PacketPolicy.Packet) :
    Decidable (exchange.Matches packet) := by
  unfold ManagementExchange.Matches
  infer_instance

def Deployment.ManagementExchangeFor (d : Deployment) (packet : PacketPolicy.Packet) :
    Option ManagementExchange :=
  d.managementExchanges.find? (fun exchange => decide (exchange.Valid d ∧ exchange.Matches packet))

def Deployment.ManagementMetadataBound (d : Deployment) (packet : PacketPolicy.Packet) : Prop :=
  PacketClass packet = .management → packet.connectionState = "established" →
    ∃ exchange ∈ d.managementExchanges, exchange.Valid d ∧ exchange.Matches packet

def Deployment.ManagementSessionsCoherent (d : Deployment) : Prop :=
  (∀ exchange ∈ d.managementExchanges, exchange.Valid d) ∧
  (∀ first ∈ d.managementExchanges, ∀ second ∈ d.managementExchanges,
    first.id = second.id → first = second) ∧
  (∀ first ∈ d.managementHistory, ∀ second ∈ d.managementHistory,
    first.observer = second.observer → first.order = second.order → first = second)

def Deployment.Initiator (d : Deployment) (packet : PacketPolicy.Packet) : String :=
  match d.ManagementExchangeFor packet with
  | some exchange => exchange.request.sourceComponent
  | none => if packet.connectionState ∈ ["new", ""] then
      (d.PacketOwner packet packet.source).getD "external" else "external"

def Deployment.RegisteredService (d : Deployment) (packet : PacketPolicy.Packet) : Option ServiceKind :=
  ((d.services.find? (fun service => service.protocol == packet.protocol &&
    ((d.PacketOwner packet packet.destination == some service.device && packet.destinationPort == service.port) ||
      (d.PacketOwner packet packet.source == some service.device && packet.sourcePort == service.port)))).map
        ServiceRegistration.kind)

def Deployment.ObservedService (d : Deployment) (packet : PacketPolicy.Packet) : String :=
  if PacketIKE packet then "ike" else if PacketUDPESP packet then "esp" else
  match d.RegisteredService packet with
  | some .application | some .control => PacketService packet
  | some kind => kind.name
  | none => PacketService packet

def Deployment.ObservedClass (d : Deployment) (packet : PacketPolicy.Packet) : TrafficClass :=
  if PacketIKE packet then .control else if PacketUDPESP packet then .protectedData else
  if d.udpBindings.any (fun binding => decide (binding.mode = .keepalive ∧ binding.WellFormed ∧ binding.Framing packet))
    then .control else
  match d.RegisteredService packet with
  | some .control | some .time => .control
  | some .application => .protectedData
  | some _ => .management
  | none =>
      if PacketClass packet = .control then .control
      else if d.devices.any (fun device => device.kind == .workstation &&
        (d.PacketOwner packet packet.source == some device.id ||
          d.PacketOwner packet packet.destination == some device.id)) then .management
      else PacketClass packet

def Deployment.RevocationEndpoint (d : Deployment) (packet : PacketPolicy.Packet) : Bool :=
  d.devices.any (fun device =>
    (d.PacketOwner packet packet.destination == some device.id ||
      d.PacketOwner packet packet.source == some device.id) &&
    device.kind == .revocationService && device.layer == some .inner)

def Deployment.Observe (d : Deployment) (packet : PacketPolicy.Packet) : Traffic :=
  { packet := packet
    ipVersion := PacketIPVersion packet
    ipProtocol := PacketIPProtocol packet
    multicast := PacketMulticast packet
    trafficClass := if d.RevocationEndpoint packet then .protectedData else d.ObservedClass packet
    sourceDevice := d.PacketOwner packet packet.source
    destinationDevice := d.PacketOwner packet packet.destination
    originator := d.Initiator packet
    service := d.ObservedService packet
    innerRevocation := d.RevocationEndpoint packet
    remoteRequest := decide (d.PacketOwner packet packet.source ≠ d.PacketOwner packet packet.destination) }

def Deployment.Supported (d : Deployment) (traffic : Traffic) : Prop :=
  traffic = d.Observe traffic.packet ∧ d.ManagementMetadataBound traffic.packet

def Deployment.AddressInventoryCoherent (d : Deployment) : Prop :=
  d.ManagementSessionsCoherent ∧
  (∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces, ∀ address,
    first.linkAddress = some address → second.linkAddress = some address → first.device = second.device) ∧
  (∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces, ∀ address,
    first.address = some address → second.address = some address → first.device = second.device) ∧
  (∀ component, d.grayWorkstation component ↔
    d.IsDevice component .workstation ∧
      ∃ interface ∈ d.interfaces, interface.device = component ∧ interface.zone = .gray ∧
        interface.managementNetwork = true) ∧
  (∀ service ∈ d.services, ∃ device ∈ d.devices, device.id = service.device) ∧
  (∀ first ∈ d.services, ∀ second ∈ d.services,
    first.device = second.device → first.protocol = second.protocol →
    first.port = second.port → first.kind = second.kind)

def Deployment.GrayManagementTunnel (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ tunnel ∈ d.tunnels, tunnel.id ∈ d.grayManagementTunnels ∧
    d.intendedPeer tunnel.sender tunnel.receiver ∧
    traffic.sourceDevice = some tunnel.sender ∧ traffic.destinationDevice = some tunnel.receiver ∧
    ((tunnel.mechanism = .ipsec ∧
      (IPsecProtocol traffic ∨ d.ConfiguredUDPProtocol traffic.packet)) ∨
     (tunnel.mechanism = .macsec ∧ (PacketMKA traffic.packet ∨ PacketMACsec traffic.packet)))


def Deployment.IPsecTraffic (d : Deployment) (traffic : Traffic) : Prop :=
  IPsecProtocol traffic ∨ d.ConfiguredUDPProtocol traffic.packet

def Deployment.TunnelTraffic (d : Deployment) (traffic : Traffic) : Prop :=
  d.IPsecTraffic traffic ∨ PacketMKA traffic.packet ∨ PacketMACsec traffic.packet

def MACsecPayload (association : LayeredFrame.MACsecAssociation) (bytes : List UInt8) : Prop :=
  22 ≤ bytes.length ∧ PacketSource.field bytes 0 1 % 4 = association.associationNumber ∧
  (if PacketSource.field bytes 0 1 / 32 % 2 = 1 then
    30 ≤ bytes.length ∧ PacketSource.field bytes 6 8 = association.sci
  else True)

def MKAPayloadSCI (association : LayeredFrame.MACsecAssociation) (bytes : List UInt8) : Prop :=
  36 ≤ bytes.length ∧ bytes[1]? = some 5 ∧
    PacketSource.field bytes 2 2 = bytes.length - 4 ∧
    PacketSource.field bytes 8 8 = association.sci

def Deployment.AssociationPeers (d : Deployment) (association : LayeredFrame.MACsecAssociation)
    (source destination : String) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ sender ∈ inventory.configuration.macIfaces, sender.transmitAssociation = some association ∧
      inventory.componentName (inventory.configuration.ip.owner sender.physicalIface) = source ∧
      ∃ receiver ∈ inventory.configuration.macIfaces,
        inventory.componentName (inventory.configuration.ip.owner receiver.physicalIface) = destination ∧
        ∃ installed ∈ receiver.receiveAssociations,
          LayeredFrame.SameMACWireIdentity association installed ∧
          ∃ tunnel ∈ d.tunnels, tunnel.id = inventory.macsecTunnel association ∧
            tunnel.mechanism = .macsec ∧ tunnel.sender = source ∧ tunnel.receiver = destination

def Deployment.LinkInnerPair (d : Deployment) (traffic : Traffic) (source destination : String) : Prop :=
  ∃ association bytes, d.AssociationPeers association source destination ∧
    traffic.packet.payloadBytes = some bytes ∧
    ((PacketMACsec traffic.packet ∧ MACsecPayload association bytes ∧
      (PacketSource.field bytes 0 1 / 32 % 2 = 0 →
        traffic.packet.source = association.sci / 65536)) ∨
     (PacketMKA traffic.packet ∧ MKAPayloadSCI association bytes ∧
       traffic.packet.source = association.sci / 65536))

def Deployment.CarrierBindingWellFormed (d : Deployment) (binding : PacketProcessing.CarrierBinding) : Prop :=
  binding.encoding.Valid ∧ binding.encoding.protocol = binding.endpoint.protocol ∧
  binding.encoding.networkProtocol = binding.endpoint.networkProtocol ∧
  (binding.endpoint.peerSession, binding.encoding.header binding.endpoint.peerSession) ∈ binding.encoding.headers ∧
  binding.endpoint.peerSession < 2^32 ∧
  (∃ interface ∈ d.interfaces, interface.device = binding.sourceEncapsulator ∧
    interface.zone = .gray ∧ interface.address = some binding.endpoint.source) ∧
  (∃ interface ∈ d.interfaces, interface.device = binding.destinationEncapsulator ∧
    interface.zone = .gray ∧ interface.address = some binding.endpoint.destination) ∧
  ∃ inventory, d.processing = some inventory ∧
    (∃ sender ∈ inventory.configuration.carriers, sender.transmit = binding.endpoint ∧
      inventory.componentName (inventory.configuration.ip.owner sender.routingIface) =
        binding.sourceEncapsulator) ∧
    (∃ receiver ∈ inventory.configuration.carriers,
      inventory.componentName (inventory.configuration.ip.owner receiver.routingIface) =
        binding.destinationEncapsulator ∧
      receiver.transmit.source = binding.endpoint.destination ∧
      receiver.transmit.destination = binding.endpoint.source ∧
      receiver.transmit.sourcePort = binding.endpoint.destinationPort ∧
      receiver.transmit.destinationPort = binding.endpoint.sourcePort ∧
      receiver.localSession = binding.endpoint.peerSession ∧
      receiver.transmit.protocol = binding.endpoint.protocol ∧
      receiver.transmit.networkProtocol = binding.endpoint.networkProtocol)

def Deployment.MKAActorPeers (d : Deployment) (sci : Nat) (source destination : String) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ endpoint ∈ inventory.mkaPeers, endpoint.actorSCI = sci ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = source ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = destination ∧
      ∃ tunnel ∈ d.tunnels, tunnel.id = endpoint.tunnel ∧ tunnel.layer = .inner ∧
        tunnel.mechanism = .macsec ∧ tunnel.sender = source ∧ tunnel.receiver = destination

def Deployment.MKAInnerPair (d : Deployment) (traffic : Traffic) (source destination : String) : Prop :=
  ∃ sci bytes, d.MKAActorPeers sci source destination ∧
    traffic.packet.payloadBytes = some bytes ∧ PacketMKA traffic.packet ∧
    traffic.packet.source = sci / 65536 ∧
    PacketSource.field bytes 8 8 = sci ∧ 36 ≤ bytes.length

def Deployment.CarrierInnerPair (d : Deployment) (traffic : Traffic)
    (source destination : String) : Prop :=
  ∃ binding ∈ d.carrierBindings, d.CarrierBindingWellFormed binding ∧
    (binding.sourceEncapsulator = source ∨
      ∃ interface, d.OwnedGrayAttachment source binding.sourceEncapsulator interface) ∧
    (binding.destinationEncapsulator = destination ∨
      ∃ interface, d.OwnedGrayAttachment binding.destinationEncapsulator destination interface) ∧
    traffic.packet.protocol = binding.endpoint.networkProtocol ∧
    traffic.packet.source = binding.endpoint.source ∧
    traffic.packet.destination = binding.endpoint.destination ∧
    traffic.packet.sourcePort = binding.endpoint.sourcePort ∧
    traffic.packet.destinationPort = binding.endpoint.destinationPort ∧
    ∃ ethernet header payload,
      PacketSource.EthernetHeaderMatches ethernet header ∧
      traffic.packet.payloadBytes = some (binding.encoding.header binding.endpoint.peerSession ++ header ++ payload) ∧
      binding.encoding.session (binding.encoding.header binding.endpoint.peerSession ++ header ++ payload) =
        some binding.endpoint.peerSession ∧
      ((d.AssociationPeers binding.association source destination ∧
        ethernet.etherType = 35045 ∧ MACsecPayload binding.association payload ∧
        (PacketSource.field payload 0 1 / 32 % 2 = 0 →
          ethernet.source = binding.association.sci / 65536)) ∨
       (d.MKAActorPeers binding.association.sci source destination ∧
        ethernet.etherType = 34958 ∧ MKAPayloadSCI binding.association payload ∧
        ethernet.source = binding.association.sci / 65536))

def Deployment.InnerPair (d : Deployment) (traffic : Traffic) (source destination : String) : Prop :=
  (traffic.sourceDevice = some source ∧ traffic.destinationDevice = some destination ∧
    (∃ interface ∈ d.interfaces, interface.device = source ∧ interface.zone = .gray ∧
      interface.PacketAddress traffic.packet = some traffic.packet.source) ∧
    ∃ interface ∈ d.interfaces, interface.device = destination ∧ interface.zone = .gray ∧
      interface.PacketAddress traffic.packet = some traffic.packet.destination) ∨
  d.LinkInnerPair traffic source destination ∨ d.MKAInnerPair traffic source destination ∨
    d.CarrierInnerPair traffic source destination

def Deployment.SameLevelInner (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source ∈ d.devices, ∃ destination ∈ d.devices,
    source.layer = some .inner ∧ destination.layer = some .inner ∧
    source.level = destination.level ∧ d.intendedPeer source.id destination.id ∧
    d.InnerPair traffic source.id destination.id

def Deployment.AppropriateInnerTunnel (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ tunnel ∈ d.tunnels, tunnel.layer = .inner ∧ d.InnerPair traffic tunnel.sender tunnel.receiver ∧
    ((tunnel.mechanism = .ipsec ∧ d.IPsecTraffic traffic) ∨
      (tunnel.mechanism = .macsec ∧
        (PacketMACsec traffic.packet ∨ PacketMKA traffic.packet ∨
          d.CarrierInnerPair traffic tunnel.sender tunnel.receiver)))


def Deployment.PermittedTunnelTraffic (d : Deployment) (traffic : Traffic) : Prop :=
  d.TunnelTraffic traffic ∨ ∃ source destination, d.CarrierInnerPair traffic source destination


def Deployment.IntendedPacketPeer (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  (∃ destination, traffic.destinationDevice = some destination ∧ d.intendedPeer device destination) ∨
  ∃ binding ∈ d.udpBindings, binding.WellFormed ∧ binding.Framing traffic.packet ∧
    binding.sourceComponent = device ∧ d.intendedPeer device binding.destinationComponent


def Deployment.IntendedMKAPeerAt (d : Deployment) (interface device : String)
    (traffic : Traffic) : Prop :=
  match d.processing with
  | none => False
  | some inventory =>
    ∃ endpoint ∈ inventory.mkaPeers,
      endpoint.sourceIface ∈ inventory.ifaces ∧ endpoint.destinationIface ∈ inventory.ifaces ∧
      inventory.ifaceName endpoint.sourceIface = interface ∧ traffic.packet.egress = interface ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = device ∧
      (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.sourceIface) ∧
      (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.destinationIface) ∧
      (∃ source ∈ d.interfaces, source.id = interface ∧ source.device = device ∧
        source.zone = .black ∧ source.linkAddress = some (endpoint.actorSCI / 65536)) ∧
      (∃ sender ∈ d.devices, sender.id = device ∧ sender.kind = .macsec ∧ sender.layer = some .outer) ∧
      ∃ receiver ∈ d.devices, receiver.kind = .macsec ∧ receiver.layer = some .outer ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = receiver.id ∧
        (∃ destination ∈ d.interfaces,
          destination.id = inventory.ifaceName endpoint.destinationIface ∧
          destination.device = receiver.id ∧ destination.zone = .black) ∧
        (∃ tunnel ∈ d.tunnels, tunnel.id = endpoint.tunnel ∧ tunnel.layer = .outer ∧
          tunnel.mechanism = .macsec ∧ tunnel.sender = device ∧ tunnel.receiver = receiver.id) ∧
        d.intendedPeer device receiver.id ∧ traffic.packet.MKAFraming endpoint.actorSCI ∧
        traffic.packet.destination = 1652522221571 ∧
        traffic.packet.payloadBytes.bind (fun bytes => bytes[0]?) = some 3 ∧
        traffic.trafficClass = .control ∧ d.policyApproved device traffic

def Deployment.IntendedPacketPeerAt (d : Deployment) (interface device : String)
    (traffic : Traffic) : Prop :=
  d.IntendedPacketPeer device traffic ∨ d.IntendedMKAPeerAt interface device traffic


def Deployment.LinkPath (_d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) : Prop :=
  (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = iface) ∨
  (∃ next ∈ inventory.ifaces,
    inventory.configuration.bridge iface next ∨ inventory.configuration.bridge next iface) ∨
  (∃ carrier ∈ inventory.configuration.carriers, carrier.virtualIface = iface)

def Deployment.LinkTransit (_d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) (direction : Direction) : Prop :=
  (∃ next ∈ inventory.ifaces,
    if direction = .inbound then inventory.configuration.bridge iface next
    else inventory.configuration.bridge next iface) ∨
  (∃ carrier ∈ inventory.configuration.carriers, carrier.virtualIface = iface) ∨
  ∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = iface

def Deployment.LinkCapable (d : Deployment) (interface : String) (direction : Direction)
    (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface ∧
      ((PacketIsEthernet traffic.packet ∧ d.LinkTransit inventory iface direction) ∨
       (PacketMKA traffic.packet ∧
        ∃ endpoint ∈ inventory.mkaPeers,
          (if direction = .outbound then endpoint.sourceIface = iface
            else endpoint.destinationIface = iface) ∧
          ∃ bytes, traffic.packet.payloadBytes = some bytes ∧ 36 ≤ bytes.length ∧
            PacketSource.field bytes 8 8 = endpoint.actorSCI ∧
            traffic.packet.source = endpoint.actorSCI / 65536) ∨
       (PacketMACsec traffic.packet ∧
        ∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = iface ∧
          ∃ association bytes, traffic.packet.payloadBytes = some bytes ∧
            MACsecPayload association bytes ∧
            (PacketSource.field bytes 0 1 / 32 % 2 = 0 →
              traffic.packet.source = association.sci / 65536) ∧
            if direction = .outbound then
              mac.transmitAssociation = some association ∧
                mac.settings.controlledPortEnabled = true ∧
                mac.settings.protectFrames = true ∧ mac.settings.encryptFrames = true ∧
                mac.settings.confidentialityOffset = 0
            else association ∈ mac.receiveAssociations ∧ mac.validateStrict = true))

def Deployment.LinkOperation (d : Deployment) (interface : String) (direction : Direction)
    (traffic : Traffic) : Prop :=
  d.LinkCapable interface direction traffic ∧
  ∃ inventory, d.processing = some inventory ∧
    ∃ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface ∧
      LinkAdmission.Admitted inventory.configuration.linkPolicies iface
        (direction = .outbound) traffic.packet

def HookDirection (hook : PacketProcessing.Hook) (direction : Direction) : Prop :=
  (hook = .input ∧ direction = .inbound) ∨
  (hook = .output ∧ direction = .outbound) ∨ hook = .forward ∨ hook = .link

def Interface.HookApplies (interface : Interface) (hook : PacketProcessing.Hook)
    (direction : Direction) : Prop :=
  HookDirection hook direction ∧
  hook ≠ .link ∧ interface.address.isSome = true

def Deployment.PolicyCoverage (d : Deployment) (interface : Interface) : Prop :=
  ∀ direction hook, interface.HookApplies hook direction → ∃ policy ∈ d.policies,
    policy.interface = interface.id ∧ policy.direction = direction ∧ policy.hook = hook ∧
    ∀ other ∈ d.policies, other.interface = interface.id → other.direction = direction →
      other.hook = hook → other = policy

def PacketAtHook (name : String) (direction : Direction) (hook : PacketProcessing.Hook)
    (packet : PacketPolicy.Packet) : Prop :=
  HookDirection hook direction ∧
  match hook with
  | .input => packet.ingress = name ∧ packet.egress = "" ∧ packet.outboundPolicies = []
  | .output => packet.egress = name ∧ packet.ingress = "" ∧ packet.inboundPolicies = []
  | .forward => if direction = .inbound then packet.ingress = name else packet.egress = name
  | .link =>
      (if direction = .inbound then packet.ingress = name ∧ packet.egress = ""
       else packet.egress = name ∧ packet.ingress = "") ∧
      packet.inboundPolicies = [] ∧ packet.outboundPolicies = []

def Deployment.HookContext (d : Deployment) (interface : String) (direction : Direction)
    (hook : PacketProcessing.Hook) (packet : PacketPolicy.Packet) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface ∧
      ∃ record ∈ d.interfaces, record.id = interface ∧
        record.device = inventory.componentName (inventory.configuration.ip.owner iface) ∧
        PacketAtHook (inventory.configuration.ip.interfaceName iface) direction hook packet

def Deployment.AcceptsAt (d : Deployment) (interface : String) (direction : Direction)
    (hook : PacketProcessing.Hook) (traffic : Traffic) : Prop :=
  d.Supported traffic ∧ d.HookContext interface direction hook traffic.packet ∧
  if hook = .link then d.LinkOperation interface direction traffic else
  ∃ policy ∈ d.policies,
    policy.interface = interface ∧ policy.direction = direction ∧ policy.hook = hook ∧
    (∀ other ∈ d.policies, other.interface = interface → other.direction = direction →
      other.hook = hook → other = policy) ∧ policy.Accepts traffic

def Deployment.Accepts (d : Deployment) (interface : String) (direction : Direction)
    (traffic : Traffic) : Prop :=
  ∃ hook, d.AcceptsAt interface direction hook traffic

def AtomAtHook (hook : PacketProcessing.Hook) : PacketPolicy.Atom → Prop
  | .egress _ | .outboundPolicy _ => hook ≠ .input
  | .ingress _ | .inboundPolicy _ => hook ≠ .output
  | _ => True


def Deployment.ProcessingCoherent (d : Deployment) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    (∀ endpoint ∈ inventory.mkaPeers,
      endpoint.sourceIface ∈ inventory.ifaces ∧ endpoint.destinationIface ∈ inventory.ifaces ∧
      (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.sourceIface) ∧
      (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.destinationIface) ∧
      ∃ interface ∈ d.interfaces, interface.id = inventory.ifaceName endpoint.sourceIface ∧
        interface.linkAddress = some (endpoint.actorSCI / 65536)) ∧
    (∀ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec →
      ∃ endpoint ∈ inventory.mkaPeers, endpoint.tunnel = tunnel.id ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = tunnel.sender ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = tunnel.receiver) ∧
    (∀ iface ∈ inventory.ifaces, ∃ interface ∈ d.interfaces,
      interface.id = inventory.ifaceName iface ∧
      interface.device = inventory.componentName (inventory.configuration.ip.owner iface)) ∧
    (∀ interface ∈ d.interfaces, ∃ iface ∈ inventory.ifaces,
      inventory.ifaceName iface = interface.id ∧
      inventory.componentName (inventory.configuration.ip.owner iface) = interface.device) ∧
    (∀ first ∈ inventory.ifaces, ∀ second ∈ inventory.ifaces,
      inventory.ifaceName first = inventory.ifaceName second → first = second) ∧
    (∀ packet payload, inventory.configuration.networkBytes (.datagram packet) payload = packet.networkBytes) ∧
    (∀ interface ∈ d.interfaces, ∃ mtu, interface.mtu = some mtu ∧ 0 < mtu) ∧
    (∀ iface ∈ inventory.ifaces, ∀ policy ∈ inventory.configuration.ip.outbound iface,
      ∃ size ∈ inventory.ipsecSizes, size.iface = iface ∧ size.policy = policy) ∧
    (∀ size ∈ inventory.ipsecSizes, size.Valid ∧ size.iface ∈ inventory.ifaces ∧
      size.policy ∈ inventory.configuration.ip.outbound size.iface) ∧
    (∀ route ∈ inventory.configuration.ip.routes,
      route.ingress ∈ inventory.ifaces ∧ route.egress ∈ inventory.ifaces ∧
      inventory.configuration.ip.owner route.ingress = inventory.configuration.ip.owner route.egress) ∧
    (∀ iface ∈ inventory.ifaces, ∀ address,
      inventory.configuration.ip.localAddress iface address ↔
        ∃ interface ∈ d.interfaces,
          interface.device = inventory.componentName (inventory.configuration.ip.owner iface) ∧
          interface.HasLocalAddress address) ∧
    (∀ first ∈ inventory.ifaces, ∀ second ∈ inventory.ifaces,
      inventory.configuration.ip.owner first = inventory.configuration.ip.owner second →
      inventory.configuration.ip.forwardRules first = inventory.configuration.ip.forwardRules second ∧
      inventory.configuration.ip.forwardFallback first = inventory.configuration.ip.forwardFallback second) ∧
    (∀ policy ∈ d.policies, ∃ interface ∈ d.interfaces, ∃ iface ∈ inventory.ifaces,
      interface.id = policy.interface ∧ inventory.ifaceName iface = interface.id ∧
      interface.HookApplies policy.hook policy.direction ∧
      (∀ rule ∈ policy.rules, ∀ atom ∈ rule.atoms, AtomAtHook policy.hook atom) ∧
      match policy.hook with
      | .input =>
          policy.rules = inventory.configuration.ip.inputRules iface ∧
          policy.defaultVerdict = inventory.configuration.ip.inputFallback iface
      | .output =>
          policy.rules = inventory.configuration.ip.outputRules iface ∧
          policy.defaultVerdict = inventory.configuration.ip.outputFallback iface
      | .forward =>
          policy.rules = inventory.configuration.ip.forwardRules iface ∧
          policy.defaultVerdict = inventory.configuration.ip.forwardFallback iface
      | .link => False)

def Deployment.LinkPoliciesComplete (d : Deployment) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    (∀ iface ∈ inventory.ifaces, d.LinkPath inventory iface →
      ∃ policy, LinkAdmission.lookup inventory.configuration.linkPolicies iface = some policy) ∧
    (∀ entry ∈ inventory.configuration.linkPolicies, entry.1 ∈ inventory.ifaces ∧
      d.LinkPath inventory entry.1) ∧
    (∀ first ∈ inventory.configuration.linkPolicies,
      ∀ second ∈ inventory.configuration.linkPolicies, first.1 = second.1 → first = second)

def Deployment.LocalSourceAddress (d : Deployment) (component : String)
    (packet : PacketPolicy.Packet) : Prop :=
  (∃ interface ∈ d.interfaces, interface.device = component ∧
    interface.HasLocalAddress packet.source) ∨
  (packet.source = 0 ∧ packet.protocol = "udp" ∧
    packet.sourcePort = 68 ∧ packet.destinationPort = 67) ∨
  (packet.source = 2^128 ∧ packet.protocol = "icmpv6" ∧ packet.icmpType = 135)

def Deployment.LocalBodySource (d : Deployment) (component iface : String)
    (body : LayeredFrame.Body) : Prop :=
  ∃ interface ∈ d.interfaces, interface.id = iface ∧ interface.device = component ∧
    match body with
    | .datagram header => d.LocalSourceAddress component header
    | .ethernet header => interface.linkAddress = some header.source
    | _ => False

def Deployment.ContextLocation (d : Deployment) (inventory : PacketProcessing.Inventory)
    (interface : Interface) (direction : Direction) (context : PacketProcessing.Context) : Prop :=
  context.entry.iface ∈ inventory.ifaces ∧ context.state.iface ∈ inventory.ifaces ∧
  context.state.enteredIface ∈ inventory.ifaces ∧
  inventory.componentName (inventory.configuration.ip.owner context.state.iface) = interface.device ∧
  inventory.configuration.ip.owner context.state.enteredIface =
    inventory.configuration.ip.owner context.state.iface ∧
  (match context.hook, direction with
   | .input, .inbound =>
       inventory.ifaceName context.state.enteredIface = interface.id ∧
       ∃ endpoint ∈ d.interfaces, endpoint.device = interface.device ∧
         endpoint.address = some context.header.destination
   | .forward, .inbound => inventory.ifaceName context.state.enteredIface = interface.id
   | .forward, .outbound => inventory.ifaceName context.state.iface = interface.id
   | .output, .outbound =>
       inventory.ifaceName context.state.iface = interface.id ∧
       d.LocalSourceAddress interface.device context.header
   | _, _ => False)

def Deployment.SupportedAt (d : Deployment) (interface : Interface) (direction : Direction)
    (context : PacketProcessing.Context) (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    interface ∈ d.interfaces ∧ interface.HookApplies context.hook direction ∧
    context.AtHook inventory.configuration ∧ d.ContextLocation inventory interface direction context ∧
    context.raw.PreHookValid (context.Packet inventory.configuration) context.hook ∧
    traffic.packet = context.Packet inventory.configuration ∧ d.Supported traffic

def Deployment.SupportedLinkAt (d : Deployment) (interface : Interface) (direction : Direction)
    (context : PacketProcessing.LinkContext) (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    context.iface ∈ inventory.ifaces ∧ context.peerIface ∈ inventory.ifaces ∧
    interface ∈ d.interfaces ∧ interface.linkAddress.isSome = true ∧
    d.LinkPath inventory context.iface ∧
    inventory.ifaceName context.iface = interface.id ∧
    inventory.componentName (inventory.configuration.ip.owner context.iface) = interface.device ∧
    (if direction = .inbound then
      inventory.configuration.physicalLink context.peerIface context.iface
    else inventory.configuration.physicalLink context.iface context.peerIface) ∧
    traffic.packet = context.packet ∧ context.raw.PreHookValid context.packet .link ∧
    context.packet.protocol = "ethernet" ∧ d.Supported traffic ∧
    PacketAtHook (inventory.configuration.ip.interfaceName context.iface) direction .link context.packet

def Deployment.IfaceMtu (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface mtu : Nat) : Prop :=
  ∃ interface ∈ d.interfaces, interface.id = inventory.ifaceName iface ∧ interface.mtu = some mtu

def Deployment.ContextSizeEligible (d : Deployment) (context : PacketProcessing.Context) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ bytes, (context.Packet inventory.configuration).networkBytes = some bytes ∧
      (context.hook = .input ∨ context.hook = .forward →
        ∃ mtu, d.IfaceMtu inventory context.state.enteredIface mtu ∧ bytes ≤ mtu) ∧
      (context.hook = .output ∨ context.hook = .forward →
        ∃ mtu, d.IfaceMtu inventory context.state.iface mtu ∧ bytes ≤ mtu ∧
          ∀ policy ∈ Execution.selectedAssociations
              (inventory.configuration.ip.outbound context.state.iface) context.header,
            ∃ size ∈ inventory.ipsecSizes, size.Valid ∧ size.iface = context.state.iface ∧ size.policy = policy ∧
              size.EncodedSize bytes ≤ mtu)

def Deployment.LinkSizeEligible (d : Deployment) (context : PacketProcessing.LinkContext) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ mtu, d.IfaceMtu inventory context.iface mtu ∧
      ∃ header rawHeader payload, context.raw = .ethernet header rawHeader payload ∧
        payload.length ≤ mtu

def NativeIngressAttachment (inventory : PacketProcessing.Inventory) (iface : Nat) : Prop :=
  (∃ peer ∈ inventory.ifaces, inventory.configuration.physicalLink peer iface) ∨
  (∃ mac ∈ inventory.configuration.macIfaces, mac.logicalIface = iface) ∨
  ∃ carrier ∈ inventory.configuration.carriers, carrier.virtualIface = iface

def Deployment.NativeArrivalEligible (d : Deployment) (inventory : PacketProcessing.Inventory)
    (state : MultiProtocolExecution.State) : Prop :=
  NativeIngressAttachment inventory state.iface ∨
    ∃ header, state.frame.visibleHeader = some header ∧
      d.LocalSourceAddress (inventory.componentName (inventory.configuration.ip.owner state.iface)) header

def Deployment.InboundIPsecBoundary (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) : Prop :=
  ∃ interface ∈ d.interfaces, interface.id = inventory.ifaceName iface ∧
    ∃ device ∈ d.devices, device.id = interface.device ∧ device.kind = .vpn ∧
      ((device.layer = some .outer ∧ interface.zone = .black) ∨
        (device.layer = some .inner ∧ interface.zone = .gray))

def Deployment.InboundIPsecRequired (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) (header : PacketPolicy.Packet) : Prop :=
  d.InboundIPsecBoundary inventory iface ∨
    ∃ policy ∈ inventory.configuration.ip.inbound iface, policy.matches header = true

def Deployment.ContextIngressEligible (d : Deployment) (context : PacketProcessing.Context)
    (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧ context.entry.frame.HeadersCoherent ∧
    (context.hook = .forward → d.NativeArrivalEligible inventory context.entry) ∧
    (context.hook = .forward → d.InboundIPsecRequired inventory context.entry.iface context.header →
      (∃ entered, MultiProtocolExecution.Step inventory.configuration context.entry .decryptIPsec entered ∧
        MultiProtocolExecution.Step inventory.configuration entered .route context.state ∧
        PacketProcessing.InputAdmitted inventory.configuration context.entry) ∨
      (traffic.trafficClass = .control ∧
        d.policyApproved (inventory.componentName
          (inventory.configuration.ip.owner context.entry.iface)) traffic ∧
        inventory.configuration.ip.localAddress context.entry.iface traffic.packet.destination))

def Deployment.PacketEligibleAt (d : Deployment) (interface : Interface) (direction : Direction)
    (hook : PacketProcessing.Hook) (traffic : Traffic) : Prop :=
  (∃ context, context.hook = hook ∧ d.SupportedAt interface direction context traffic ∧
    d.ContextSizeEligible context ∧ d.ContextIngressEligible context traffic) ∨
  (hook = .link ∧ ∃ context, d.SupportedLinkAt interface direction context traffic ∧ d.LinkSizeEligible context)

def Deployment.HeaderEligible (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  ∀ device ∈ d.devices, device.id = interface.device →
    (device.kind = .vpn → traffic.ipVersion = some 4 → traffic.ipProtocol ∈ [6, 17, 50, 1]) ∧
    (device.kind = .vpn → traffic.ipVersion = some 6 →
      traffic.packet.ipv6NextHeader ∈ [50, 6, 17, 58]) ∧
    (device.kind = .vpn → device.layer = some .outer → traffic.ipVersion = some 4 →
      d.dropIPv4Options device.id = true → traffic.packet.ipv4HeaderWords = 5) ∧
    (device.layer = some .outer → interface.zone = .black → traffic.multicast = false)

def Deployment.UDPBindingsCoherent (d : Deployment) : Prop :=
  (∀ binding ∈ d.udpBindings, binding.WellFormed ∧
    (∃ source ∈ d.devices, source.id = binding.sourceComponent) ∧
    (∃ destination ∈ d.devices, destination.id = binding.destinationComponent) ∧
    (∃ interface ∈ d.interfaces, interface.device = binding.sourceComponent ∧
      interface.address = some binding.sourceOriginalAddress) ∧
    (∃ interface ∈ d.interfaces, interface.device = binding.destinationComponent ∧
      interface.address = some binding.destinationOriginalAddress)) ∧
  (∀ first ∈ d.udpBindings, ∀ second ∈ d.udpBindings,
    first.id = second.id → first = second)

def NativeExecutionBinding.ProcessingBound {S A : Type} (binding : NativeExecutionBinding S A)
    (d : Deployment) : Prop :=
  d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∃ inventory, d.processing = some inventory ∧
    inventory.configuration = binding.configuration ∧
    inventory.ifaceName = binding.ifaceName ∧ inventory.componentName = binding.componentName ∧
    inventory.macsecTunnel = binding.macsecTunnel ∧
    (∀ carrier ∈ d.carrierBindings, d.CarrierBindingWellFormed carrier) ∧
    (∀ iface ∈ inventory.ifaces, ∃ interface ∈ d.interfaces,
      interface.id = binding.ifaceName iface ∧
      interface.device = binding.componentName (binding.configuration.ip.owner iface)) ∧
    (∀ mac ∈ binding.configuration.macIfaces,
      mac.physicalIface ∈ inventory.ifaces ∧ mac.logicalIface ∈ inventory.ifaces) ∧
    (∀ size ∈ inventory.ipsecSizes, ∀ installation ∈ binding.ipsecInstallations,
      installation.direction = .outbound →
      installation.device = binding.configuration.ip.owner size.iface →
      Execution.StateBindsPolicy installation.association size.policy →
      ∃ material, binding.ipsecKeyMaterial installation = some material ∧
        material.transform.encryptionAlgorithm = "rfc4106(gcm(aes))" ∧
        material.transform.encryptionKeyBits = 256 ∧ material.transform.saltBytes = 4 ∧
        material.transform.authenticationBits = 128 ∧ material.transform.integrityAlgorithm = none)


def ExecutionModel.ProtectedPayload {S A : Type} (model : ExecutionModel S A)
    (d : Deployment) (payload : PayloadId) : Prop :=
  ∃ network ∈ d.networks, model.native.origin payload.originDomain = .red network.id

def ExecutionModel.GenuineControl {S A : Type} (model : ExecutionModel S A)
    (payload : PayloadId) : Prop :=
  ∃ component protocol, model.native.origin payload.originDomain = .control component protocol

def NativeExecutionBinding.SourceBody {S A : Type} (_binding : NativeExecutionBinding S A)
    (body : LayeredFrame.Body) : Prop :=
  (∃ header, body = .datagram header) ∨ (∃ header, body = .ethernet header)

def BodyControlProtocol (d : Deployment) (body : LayeredFrame.Body) (protocol : String) : Prop :=
  (∃ header, body = .datagram header ∧ protocol = header.protocol ∧
    (d.Observe header).trafficClass = .control) ∨
  (∃ header, body = .ethernet header ∧
    ((header.etherType = 34958 ∧ protocol = "eapol") ∨
      (header.etherType = 2054 ∧ protocol = "arp")))

def BodyManagement (d : Deployment) (body : LayeredFrame.Body) : Prop :=
  ∃ header, body = .datagram header ∧ (d.Observe header).trafficClass = .management

def NativeExecutionBinding.SourceRequestAllowed {S A : Type}
    (binding : NativeExecutionBinding S A) (d : Deployment) (request : PacketSource.Request) : Prop :=
  binding.SourceBody request.body ∧ request.PayloadMatches ∧
  match binding.origin request.originDomain with
  | .red network => binding.sourceEntry request.iface = some network ∧
      ∃ red ∈ d.networks, red.id = network
  | .management component => BodyManagement d request.body ∧
      binding.componentName (binding.configuration.ip.owner request.iface) = component ∧
      d.LocalBodySource component (binding.ifaceName request.iface) request.body
  | .control component protocol => BodyControlProtocol d request.body protocol ∧
      binding.componentName (binding.configuration.ip.owner request.iface) = component ∧
      d.LocalBodySource component (binding.ifaceName request.iface) request.body

def SourceOutputPhase : LayeredFrame.Body → Execution.DatapathStage
  | .ethernet _ => .ready
  | _ => .localOutput

def NativeExecutionBinding.SourceState {S A : Type}
    (binding : NativeExecutionBinding S A) (request : PacketSource.Request)
    (datagram : PacketSource.Datagram) : MultiProtocolExecution.State :=
  { initialEntry := true, iface := request.iface,
    datapathStage := match binding.origin request.originDomain with
      | .red _ => .received
      | .management _ | .control _ _ => SourceOutputPhase datagram.body
    frame := { payload := PayloadCode datagram.application, originDomain := request.originDomain, body := datagram.body }
    enteredIface := request.iface, authenticated := [],
    tracking := (datagram.body.originalHeader.map PacketPolicy.Packet.connectionState).getD "new" }

def NativeExecutionBinding.SourceDatagram {S A : Type}
    (binding : NativeExecutionBinding S A) (d : Deployment)
    (state : MultiProtocolExecution.State) : Prop :=
  ∃ request datagrams datagram,
    binding.SourceRequestAllowed d request ∧
    binding.sourceProcessing.process request = .emitted datagrams ∧ datagram ∈ datagrams ∧
    datagram.ValidFor request (binding.sourceProcessing.sourceMtu request.iface) ∧
state = binding.SourceState request datagram

def NativeExecutionBinding.SourceInitial {S A : Type} (binding : NativeExecutionBinding S A)
    (d : Deployment) (state : MultiProtocolExecution.State) : Prop :=
  state.initialEntry = true ∧ binding.SourceBody state.frame.body ∧
  binding.SourceDatagram d state ∧
  match binding.origin state.frame.originDomain with
  | .red network => state.datapathStage = .received ∧
      binding.sourceEntry state.iface = some network ∧
      ∃ red ∈ d.networks, red.id = network
  | .management component =>
      state.datapathStage = SourceOutputPhase state.frame.body ∧ BodyManagement d state.frame.body ∧
      binding.componentName (binding.configuration.ip.owner state.iface) = component ∧
      d.LocalBodySource component (binding.ifaceName state.iface) state.frame.body
  | .control component protocol =>
      state.datapathStage = SourceOutputPhase state.frame.body ∧ BodyControlProtocol d state.frame.body protocol ∧
      binding.componentName (binding.configuration.ip.owner state.iface) = component ∧
      d.LocalBodySource component (binding.ifaceName state.iface) state.frame.body

def ExecutionModel.SourceCoverage {S A : Type} (model : ExecutionModel S A)
    (d : Deployment) : Prop :=
  (∀ request, model.native.SourceRequestAllowed d request →
    (model.native.sourceProcessing.process request).Valid request
      (model.native.sourceProcessing.sourceMtu request.iface)) ∧
  (∀ request datagrams datagram, model.native.SourceRequestAllowed d request →
    model.native.sourceProcessing.process request = .emitted datagrams → datagram ∈ datagrams →
    model.native.SourceInitial d (model.native.SourceState request datagram) ∧
    ∃ start, model.initial start ∧
      model.native.state start = model.native.SourceState request datagram ∧
      model.sourceRecord start = some (request, datagram)) ∧
  (∀ state, model.native.SourceInitial d state →
    ∃ start, model.initial start ∧ model.native.state start = state) ∧
  (∀ start, model.initial start →
    model.native.SourceInitial d (model.native.state start) ∧
    ∃ request datagrams datagram,
      model.sourceRecord start = some (request, datagram) ∧
      model.native.SourceRequestAllowed d request ∧
      model.native.sourceProcessing.process request = .emitted datagrams ∧ datagram ∈ datagrams ∧
      model.native.state start = model.native.SourceState request datagram) ∧
  (∀ network ∈ d.networks, ∃ request datagrams,
    model.native.SourceRequestAllowed d request ∧ request.application ≠ [] ∧
    model.native.origin request.originDomain = .red network.id ∧
    model.native.sourceProcessing.process request = .emitted datagrams)

def ExecutionModel.CoversDeployment {S A : Type} (model : ExecutionModel S A)
    (d : Deployment) : Prop :=
  model.native.ProcessingBound d ∧ model.Faithful ∧ model.NativeStepCoverage ∧ model.SourceCoverage d ∧ model.history.Valid ∧
  d.InterfaceLinksWellFormed ∧ d.LinkPoliciesComplete ∧
  (∃ inventory, d.processing = some inventory ∧
    model.native.configuration.HeaderGenerationKnown inventory.ifaces) ∧
  (∀ start actions state, model.initial start → model.system.MTr start actions state →
    (model.native.state state).frame.HeadersCoherent ∧
    model.native.configuration.LinkEncodingComplete (model.native.state state)) ∧
  model.native.MACsecKeyInventory ∧ model.native.IPsecKeyInventory ∧ d.networks ≠ [] ∧
  (∀ tunnel ∈ d.tunnels, d.intendedPeer tunnel.sender tunnel.receiver) ∧
  (∀ first ∈ d.devices, ∀ second ∈ d.devices, first.id = second.id → first = second) ∧
  (∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces, first.id = second.id → first = second) ∧
  (∀ first ∈ d.tunnels, ∀ second ∈ d.tunnels, first.id = second.id → first = second) ∧
  (∀ interface ∈ d.interfaces, ∃ iface,
    model.native.ifaceName iface = interface.id ∧
      model.native.componentName (model.native.configuration.ip.owner iface) = interface.device) ∧
  (∀ state : S, ∃ interface ∈ d.interfaces,
    interface.id = model.native.ifaceName (model.native.state state).iface ∧
      interface.device = model.native.componentName
        (model.native.configuration.ip.owner (model.native.state state).iface)) ∧
  (∀ first second, model.native.configuration.physicalLink first second →
    d.physicalLink (model.native.ifaceName first) (model.native.ifaceName second)) ∧
  (∀ iface network, model.native.sourceEntry iface = some network ↔
    ∃ interface ∈ d.interfaces, interface.id = model.native.ifaceName iface ∧
      interface.zone = .red ∧ interface.managementNetwork = false ∧ ∃ red ∈ d.networks, red.id = network ∧
        interface.device ∈ red.innerComponents) ∧
  (∀ iface ∈ model.native.configuration.macIfaces, ∀ association,
    iface.transmitAssociation = some association →
    ∃ tunnel ∈ d.tunnels, tunnel.id = model.native.macsecTunnel association ∧
      tunnel.mechanism = .macsec ∧
      tunnel.keyContext = model.native.keyName association.keyGeneration ∧
      tunnel.sender = model.native.componentName
        (model.native.configuration.ip.owner iface.physicalIface) ∧
      ∀ peer ∈ model.native.configuration.macIfaces,
        (∃ installed ∈ peer.receiveAssociations,
          LayeredFrame.SameMACWireIdentity association installed) →
        tunnel.receiver = model.native.componentName
          (model.native.configuration.ip.owner peer.physicalIface)) ∧
  (∀ iface association policy,
    (association ∈ model.native.configuration.ip.outboundStates iface ∧
      policy ∈ model.native.configuration.ip.outbound iface ∨
      association ∈ model.native.configuration.ip.inboundStates iface ∧
      policy ∈ model.native.configuration.ip.inbound iface) →
    Execution.StateBindsPolicy association policy →
    ∃ tunnel ∈ d.tunnels, tunnel.id = model.native.ipsecTunnel (policy.seal association) ∧
      tunnel.mechanism = .ipsec ∧
      d.AddressOwner association.sender = some tunnel.sender ∧
      d.AddressOwner association.receiver = some tunnel.receiver)

end TDN.Compliance
