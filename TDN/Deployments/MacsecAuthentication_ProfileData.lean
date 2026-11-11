import TDN.Deployments.MacsecProtection_ProfileData
import TDN.Requirements.VerifiedMacsecAuthentication

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

structure SetupEventData where
  position : Nat
  component : String
  observer : String
  localPosition : Nat
  source : String
  kind : String
  sender : String
  receiver : String
  message : List UInt8
  installation : String

structure CaptureData where
  profile : MacsecProtection.ProfileRecords
  collection : String
  epoch : String
  session : String
  keyServer : String
  cak : String
  sak : String
  material : List UInt8
  tlsInput : TLSHandshakeInput
  masterSessionKey : String
  backendInput : EAPBackendInput
  historyRecords : List SetupEventData
  dependencies : List (Nat × Nat)
  setupRecords : List MACsecSetupRecord

set_option maxRecDepth 200000 in
load_network_records forward : CaptureData from
  "../../data/evidence/macsecAuthentication/MacsecAuthenticationProfiles.json" ["forward"]
set_option maxRecDepth 200000 in
load_network_records reverse : CaptureData from
  "../../data/evidence/macsecAuthentication/MacsecAuthenticationProfiles.json" ["reverse"]

def CaptureData.exchange (capture : CaptureData) : EAPExchange :=
  { input := capture.tlsInput
    verified :=
      { session := capture.tlsInput.session
        device := capture.tlsInput.device
        server := capture.tlsInput.server
        deviceCertificate := capture.tlsInput.deviceCertificate
        serverCertificate := capture.tlsInput.serverCertificate
        deviceIdentity := capture.tlsInput.deviceIdentity
        serverIdentity := capture.tlsInput.serverIdentity
        transcript := capture.tlsInput.transcript
        masterSessionKey := capture.masterSessionKey } }

def CaptureData.backend (capture : CaptureData) : EAPBackendDelivery :=
  { input := capture.backendInput
    verified :=
      { session := capture.backendInput.session
        server := capture.backendInput.server
        authenticator := capture.backendInput.authenticator
        supplicant := capture.backendInput.supplicant
        masterSessionKey := capture.backendInput.masterSessionKey } }

noncomputable def tlsPrimitive : TLSPrimitive :=
  { mutuallyAuthenticate := fun input =>
      @ite (Option TLSVerifiedSession) (input = forward.tlsInput) (Classical.propDecidable _)
        (some forward.exchange.verified)
        (@ite (Option TLSVerifiedSession) (input = reverse.tlsInput) (Classical.propDecidable _)
          (some reverse.exchange.verified) none)
    authenticateBackendDelivery := fun input =>
      @ite (Option EAPBackendVerified) (input = forward.backendInput) (Classical.propDecidable _)
        (some forward.backend.verified)
        (@ite (Option EAPBackendVerified) (input = reverse.backendInput) (Classical.propDecidable _)
          (some reverse.backend.verified) none)
    supportsRole := fun endpoint _ => endpoint == "P0" || endpoint == "P1"
    deriveCAK := fun key => if key = forward.masterSessionKey then forward.cak
      else if key = reverse.masterSessionKey then reverse.cak else "" }

def endpointCertificate (endpoint : String) : String :=
  if endpoint = "P0" then reverse.tlsInput.deviceCertificate else forward.tlsInput.deviceCertificate

def endpointIdentity (endpoint : String) : Trust.Identity SecurityLevel String :=
  if endpoint = "P0" then reverse.tlsInput.deviceIdentity else forward.tlsInput.deviceIdentity

def CaptureData.authenticationFor (capture : CaptureData) (device peer : String) : MACsecAuthentication :=
  { device := device, peer := peer, method := .eapTLS, cak := capture.cak, peerCAK := capture.cak
    server := "AS", deviceCertificate := endpointCertificate device, peerCertificate := endpointCertificate peer
    serverCertificate := capture.tlsInput.serverCertificate
    masterSessionKey := capture.masterSessionKey, peerMasterSessionKey := capture.masterSessionKey
    deviceIdentity := endpointIdentity device, peerIdentity := endpointIdentity peer
    serverIdentity := capture.tlsInput.serverIdentity
    eapSupplicant := capture.tlsInput.device, eapAuthenticator := capture.backendInput.authenticator
    backendDelivery := capture.backend, exchanges := [forward.exchange, reverse.exchange]
    supportedRoles := [.supplicant, .authenticator], keyServer := capture.keyServer
    secureAssociationKey := capture.sak, serverAttachments := [("central-site", .gray)] }

def CaptureData.authentication (capture : CaptureData) : List MACsecAuthentication :=
  [capture.authenticationFor "P0" "P1", capture.authenticationFor "P1" "P0"]

def SetupEventData.event (record : SetupEventData) (capture : CaptureData) : NetworkEvent :=
  if record.kind = "verified" then .eapTLSVerified capture.session capture.tlsInput.device "AS"
      capture.tlsInput.deviceCertificate capture.tlsInput.serverCertificate capture.masterSessionKey
  else if record.kind = "delivered" then .eapKeyDelivered capture.session "AS"
      capture.backendInput.authenticator capture.tlsInput.device capture.masterSessionKey
  else if record.kind = "derived" then .deriveCAK capture.session record.component capture.masterSessionKey capture.cak
  else if record.kind = "authenticated" then .authenticate capture.keyServer capture.tlsInput.device capture.cak
  else if record.kind = "issued" then .issueSAK capture.keyServer capture.tlsInput.device capture.sak
  else if record.kind = "installed" then .installSAK record.component capture.sak record.installation capture.epoch
  else if record.kind = "send" then .historySend capture.session record.sender record.receiver record.message
  else if record.kind = "receive" then .historyReceive capture.session record.sender record.receiver record.message
  else .encrypt ⟨0, 0⟩ "unrecognized-history-record"

def CaptureData.history (capture : CaptureData) : ObservedHistory :=
  { stream := capture.collection, epoch := capture.epoch, cut := capture.historyRecords.length
    entries := capture.historyRecords.map (fun record =>
      { source := record.source, observer := record.observer, localPosition := record.localPosition
        component := record.component, position := record.position, epoch := capture.epoch
        session := some capture.session, event := record.event capture })
    dependencies := capture.dependencies }

def CaptureData.prototype (capture : CaptureData) : DeviceExecutionBinding MultiProtocolForwarding.State MultiProtocolForwarding.Action :=
  { capture.profile.prototype with
    macsecEpoch := some capture.epoch
    macsecKeyMaterial := fun _ => some capture.material, keyName := fun _ => capture.sak }

def CaptureData.deployment (capture : CaptureData) : Deployment :=
  { capture.profile.deployment with
    certificateAuthenticated := fun endpoint => endpoint == "P0" || endpoint == "P1"
    preSharedCAKAuthenticated := fun _ => false
    networkAttachment := fun endpoint site zone => endpoint = "AS" ∧ site = "central-site" ∧ zone = .gray }

def CaptureData.model (capture : CaptureData) :=
  { StandardDataPlaneBridge.model capture.prototype (List.range capture.profile.ifaceData.length)
      capture.deployment capture.history with
    macsecInstallationHistory := capture.setupRecords.map MACsecSetupRecord.installation
    historicalKeyMaterial := fun reference => if reference = capture.sak then some capture.material else none }

def SupportedCapture (capture : CaptureData) : Prop := capture = forward ∨ capture = reverse

end TDN.Deployments.MacsecAuthentication
