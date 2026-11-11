import TDN.Deployments.MacsecAuthentication_DeploymentCoverage
import TDN.Requirements.DeviceForwardingTraceCoverage

set_option maxHeartbeats 4000000
set_option maxRecDepth 200000

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

def trafficHeader : PacketPolicy.Packet :=
  { source := 173735937, destination := 173735938, protocol := "udp"
    sourcePort := 10000, destinationPort := 10001, hopLimit := 64
    payloadBytes := some [7, 8], ipv4HeaderWords := 5, ingress := "", egress := "",
    matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "new" }

def CaptureData.trafficRequest (capture : CaptureData) : PacketSource.Request :=
  { iface := capture.profile.sourceIfaces[0]?.getD 0, originDomain := 0
    body := .datagram trafficHeader, application := [7, 8]
    networkHeaderBytes := 20, transportHeaderBytes := 8, mode := .datagram false }

def CaptureData.trafficDatagram (capture : CaptureData) : PacketSource.Datagram :=
  PacketSource.encodeFragmentedSourceDatagram capture.trafficRequest trafficHeader [7, 8] 1500

def CaptureData.trafficStart (capture : CaptureData) : MultiProtocolForwarding.State :=
  capture.model.native.SourceState capture.trafficRequest capture.trafficDatagram

def CaptureData.trafficEntered (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficStart with initialEntry := false, datapathStage := .ingress }

def CaptureData.sender (capture : CaptureData) : MACIface :=
  capture.profile.macIfaces.headD ⟨0, 0, ⟨false, false, false, 0⟩, none, [], true⟩
def CaptureData.receiver (capture : CaptureData) : MACIface :=
  (capture.profile.macIfaces.drop 1).headD capture.sender
def CaptureData.association (capture : CaptureData) : MACsecAssociation :=
  capture.sender.transmitAssociation.getD ⟨0, 0, 0, 0⟩

def CaptureData.trafficRoute (capture : CaptureData) : DataPlaneForwarding.FibRoute :=
  ⟨capture.profile.sourceIfaces[0]?.getD 0, capture.sender.logicalIface, 0,
    680564733841876926926749214863536422912, 0, 0, 32766⟩

def CaptureData.trafficRouted (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficEntered with
    iface := capture.sender.logicalIface, datapathStage := .routed,
    frame := capture.profile.configuration.forwardedFrame capture.trafficStart.frame }

def CaptureData.trafficFiltered (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficRouted with datapathStage := .filtered }

def CaptureData.trafficReady (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficFiltered with datapathStage := .egressReady }

def CaptureData.trafficEncrypted (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficReady with
    iface := capture.sender.physicalIface,
    frame := capture.profile.configuration.macsecFrame capture.trafficReady.frame capture.association }

def CaptureData.trafficReceived (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficEncrypted with iface := capture.receiver.physicalIface, datapathStage := .received }

def CaptureData.trafficDecrypted (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficReceived with
    iface := capture.receiver.logicalIface,
    frame := capture.profile.configuration.restoredFrame capture.trafficReceived.frame capture.trafficReady.frame.body }

def CaptureData.trafficPeerEntered (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficDecrypted with datapathStage := .ingress, enteredIface := capture.receiver.logicalIface }

def CaptureData.trafficLocalInput (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficPeerEntered with datapathStage := .localInput }

def CaptureData.trafficDelivered (capture : CaptureData) : MultiProtocolForwarding.State :=
  { capture.trafficLocalInput with datapathStage := .delivered }

lemma profile_traffic_is_source (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.model.native.SourceRequestAllowed capture.deployment capture.trafficRequest ∧
    capture.model.native.sourceProcessing.process capture.trafficRequest =
      .emitted [capture.trafficDatagram] := by
  rcases supported with rfl | rfl
  · refine ⟨⟨Or.inl ⟨trafficHeader, rfl⟩, rfl, rfl, forward.profile.networks[0], by decide, rfl⟩, rfl⟩
  · refine ⟨⟨Or.inl ⟨trafficHeader, rfl⟩, rfl, rfl, reverse.profile.networks[0], by decide, rfl⟩, rfl⟩

lemma profile_traffic_steps (capture : CaptureData) (supported : SupportedCapture capture) :
    (⟨capture.model.native.AcceptedStep⟩ : Cslib.LTS _ _).MTr capture.trafficStart
      [.receive, .route, .forwardFilter, .forwardWithoutEncap, .encryptMACsec,
        .linkTransmit, .decryptMACsec, .receive, .inputFilter, .deliver] capture.trafficDelivered := by
  have senderMember : capture.sender ∈ capture.profile.configuration.macIfaces := by
    rcases supported with rfl | rfl <;> decide
  have receiverMember : capture.receiver ∈ capture.profile.configuration.macIfaces := by
    rcases supported with rfl | rfl <;> decide
  have associationInstalled : capture.association ∈ capture.receiver.receiveAssociations := by
    rcases supported with rfl | rfl <;> decide
  have firstVisible : capture.profile.configuration.visibleHeader capture.trafficStart.frame =
      some (PacketSource.sourceHeader capture.trafficRequest trafficHeader [7, 8]) := by
    rcases supported with rfl | rfl <;> rfl
  have nextVisible : capture.profile.configuration.visibleHeader capture.trafficRouted.frame =
      some { PacketSource.sourceHeader capture.trafficRequest trafficHeader [7, 8] with hopLimit := 63 } := by
    rcases supported with rfl | rfl <;> rfl
  have peerVisible : capture.profile.configuration.visibleHeader capture.trafficDecrypted.frame =
      some { PacketSource.sourceHeader capture.trafficRequest trafficHeader [7, 8] with hopLimit := 63 } := by
    rcases supported with rfl | rfl <;> rfl
  have receiveStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficStart .receive capture.trafficEntered :=
    .receive rfl firstVisible "new"
  have routeStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficEntered .route capture.trafficRouted := by
    apply MultiProtocolForwarding.Step.route (s := capture.trafficEntered) capture.trafficRoute rfl firstVisible
    · rcases supported with rfl | rfl <;>
        unfold DataPlaneForwarding.SelectedFibRoute DataPlaneForwarding.FibRoute.matches <;> decide
    · rfl
  have filterStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficRouted .forwardFilter capture.trafficFiltered := by
    apply MultiProtocolForwarding.Step.forwardFilter rfl nextVisible
    rcases supported with rfl | rfl <;> rfl
  have readyStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficFiltered .forwardWithoutEncap capture.trafficReady :=
    .forwardWithoutEncap rfl nextVisible rfl
  have encryptStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficReady .encryptMACsec capture.trafficEncrypted := by
    apply MultiProtocolForwarding.Step.encryptMACsec capture.sender capture.association senderMember rfl rfl
    rcases supported with rfl | rfl <;> exact ⟨rfl, rfl⟩
  have linkStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficEncrypted .linkTransmit capture.trafficReceived := by
    apply MultiProtocolForwarding.Step.linkTransmit capture.receiver.physicalIface rfl
    change (_, _) ∈ capture.profile.links
    rcases supported with rfl | rfl <;> decide
  have decryptStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficReceived .decryptMACsec capture.trafficDecrypted :=
    .decryptMACsec capture.receiver capture.association capture.association _ receiverMember rfl rfl rfl
      associationInstalled ⟨rfl, rfl⟩
  have peerStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficDecrypted .receive capture.trafficPeerEntered :=
    .receive rfl peerVisible "new"
  have inputStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficPeerEntered .inputFilter capture.trafficLocalInput := by
    apply MultiProtocolForwarding.Step.inputFilter (s := capture.trafficPeerEntered) rfl peerVisible
    · rcases supported with rfl | rfl
      · exact ⟨forward.profile.interfaces[2], by decide, rfl, Or.inl rfl⟩
      · exact ⟨reverse.profile.interfaces[3], by decide, rfl, Or.inl rfl⟩
    · rcases supported with rfl | rfl <;> rfl
  have deliveredStep : MultiProtocolForwarding.Step capture.profile.configuration capture.trafficLocalInput .deliver capture.trafficDelivered := by
    apply MultiProtocolForwarding.Step.deliver 1 rfl
    · rfl
    · rcases supported with rfl | rfl <;> rfl
  have linkAdmission : ∀ iface, (iface = capture.sender.physicalIface ∨ iface = capture.receiver.physicalIface) →
      ∀ outbound, capture.profile.configuration.LinkAdmitted iface outbound capture.trafficEncrypted.frame := by
    intro iface member outbound
    refine ⟨(capture.profile.macFrames.headD (capture.association, ⟨⟨0, 0, 0, []⟩, [], []⟩)).2, ?_, ?_, ?_⟩
    · rcases supported with rfl | rfl <;> rfl
    · change LinkAdmission.Frame.DescribesBody _ (.macsec capture.association _) ∧ _
      constructor
      · rcases supported with rfl | rfl <;> dsimp only [LinkAdmission.Frame.DescribesBody] <;> decide
      · intro header impossible
        cases impossible
    · rcases member with rfl | rfl <;> rcases supported with rfl | rfl
      all_goals
        refine ⟨⟨⟨[], .allow⟩, ⟨[], .allow⟩⟩, rfl, ?_⟩
        cases outbound <;> rfl
  have decryptKeys : MACsecKeyMaterialMatches capture.model.native.macsecKeyMaterial
      capture.association capture.association := by
    refine ⟨capture.material, Or.inr ?_, rfl, rfl⟩
    rcases supported with rfl | rfl <;> decide
  have plainDeliver : capture.profile.configuration.LinkStepAdmitted capture.trafficLocalInput .deliver
      capture.trafficDelivered := by
    have visible : capture.trafficLocalInput.frame.visibleHeader =
        some { PacketSource.sourceHeader capture.trafficRequest trafficHeader [7, 8] with hopLimit := 63 } := by
      rcases supported with rfl | rfl <;> rfl
    simp [Config.LinkStepAdmitted, visible]
  refine .stepL ⟨receiveStep, by simp, by simp, by simp [Config.LinkStepAdmitted], by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨routeStep, by simp, by simp, by simp [Config.LinkStepAdmitted], ?_, by simp⟩ ?_
  · intro action stage header visible enabled
    have same : header = PacketSource.sourceHeader capture.trafficRequest trafficHeader [7, 8] :=
      Option.some.inj (visible.symm.trans firstVisible)
    subst header
    change 1 < 64
    decide
  refine .stepL ⟨filterStep, by simp, by simp, by simp [Config.LinkStepAdmitted], by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨readyStep, by simp, by simp, by simp [Config.LinkStepAdmitted], by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨encryptStep, by simp, by simp, by simp [Config.LinkStepAdmitted], by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨linkStep, by simp, by simp, ?_, by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  · refine ⟨fun _ => ⟨fun _ => linkAdmission _ (Or.inl rfl) _, fun _ => linkAdmission _ (Or.inr rfl) _, fun _ => rfl⟩, by simp, by simp, by simp⟩
  refine .stepL ⟨decryptStep, ?_, by simp, ?_, by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  · intro _
    exact ⟨capture.receiver, receiverMember, capture.association, associationInstalled,
      capture.association, capture.trafficReady.frame.body, rfl, rfl, rfl, rfl, ⟨rfl, rfl⟩, decryptKeys⟩
  · exact ⟨by simp, fun _ => linkAdmission _ (Or.inr rfl) _, by simp, by simp⟩
  refine .stepL ⟨peerStep, by simp, by simp, by simp [Config.LinkStepAdmitted], by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨inputStep, by simp, by simp, by simp [Config.LinkStepAdmitted], by simp [Config.HeaderStepAdmitted], by simp⟩ ?_
  exact .stepL ⟨deliveredStep, by simp, by simp, plainDeliver, by simp [Config.HeaderStepAdmitted], by simp⟩ .refl

theorem profile_nonempty_payload_is_delivered (capture : CaptureData) (supported : SupportedCapture capture) :
    ∃ start actions finish, capture.model.initial start ∧
      capture.model.system.MTr start actions finish ∧
      (capture.model.native.state finish).datapathStage = .delivered ∧
      (capture.model.native.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (capture.model.native.state finish).frame.body = capture.trafficDatagram.body := by
  have covered := profile_deployment_is_covered capture supported
  have source := profile_traffic_is_source capture supported
  obtain ⟨_, start, initialized, projection, _⟩ :=
    covered.2.2.2.1.2.1 capture.trafficRequest [capture.trafficDatagram] capture.trafficDatagram
      source.1 source.2 (by simp)
  obtain ⟨actions, finish, trace, final⟩ := device_trace_has_model_trace capture.model covered.2.2.1
    (profile_traffic_steps capture supported) projection
  exact ⟨start, actions, finish, initialized, trace, final ▸ rfl, final ▸ rfl, final ▸ rfl⟩

end TDN.Deployments.MacsecAuthentication
