import TDN.Deployments.MacsecProtection_DeploymentCoverage
import TDN.Requirements.DeviceForwardingTraceCoverage


namespace TDN.Deployments.MacsecProtection
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

def trafficHeader : PacketPolicy.Packet :=
  { source := 173735937, destination := 173735938, protocol := "udp"
    sourcePort := 10000, destinationPort := 10001, hopLimit := 64
    payloadBytes := some [7, 8], ipv4HeaderWords := 5, ingress := "", egress := "",
    matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "new" }

def ProfileRecords.trafficRequest (records : ProfileRecords) : PacketSource.Request :=
  { iface := records.sourceIfaces[0]?.getD 0, originDomain := 0
    body := .datagram trafficHeader, application := [7, 8]
    networkHeaderBytes := 20, transportHeaderBytes := 8, mode := .datagram false }

def ProfileRecords.trafficDatagram (records : ProfileRecords) : PacketSource.EncodedDatagram :=
  PacketSource.encodeFragmentedSourceDatagram records.trafficRequest trafficHeader [7, 8] 1500

def ProfileRecords.trafficStart (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  records.model.deviceDataPlane.SourceState records.trafficRequest records.trafficDatagram

def ProfileRecords.trafficEntered (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficStart with initialEntry := false, datapathStage := .ingress }

def ProfileRecords.sender (records : ProfileRecords) : MACIface :=
  records.macIfaces.headD ⟨0, 0, ⟨false, false, false, 0⟩, none, [], true⟩
def ProfileRecords.receiver (records : ProfileRecords) : MACIface :=
  (records.macIfaces.drop 1).headD records.sender
def ProfileRecords.association (records : ProfileRecords) : MacsecAssociation :=
  records.sender.transmitAssociation.getD ⟨0, 0, 0, 0⟩

def ProfileRecords.trafficRoute (records : ProfileRecords) : DataPlaneForwarding.FibRoute :=
  ⟨records.sourceIfaces[0]?.getD 0, records.sender.logicalIface, 0,
    680564733841876926926749214863536422912, 0, 0, 32766⟩

def ProfileRecords.trafficRouted (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficEntered with
    iface := records.sender.logicalIface, datapathStage := .routed,
    frame := records.configuration.forwardedFrame records.trafficStart.frame }

def ProfileRecords.trafficFiltered (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficRouted with datapathStage := .filtered }

def ProfileRecords.trafficReady (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficFiltered with datapathStage := .egressReady }

def ProfileRecords.trafficEncrypted (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficReady with
    iface := records.sender.physicalIface,
    frame := records.configuration.macsecFrame records.trafficReady.frame records.association }

def ProfileRecords.trafficReceived (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficEncrypted with iface := records.receiver.physicalIface, datapathStage := .received }

def ProfileRecords.trafficDecrypted (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficReceived with
    iface := records.receiver.logicalIface,
    frame := records.configuration.restoredFrame records.trafficReceived.frame records.trafficReady.frame.body }

def ProfileRecords.trafficPeerEntered (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficDecrypted with datapathStage := .ingress, enteredIface := records.receiver.logicalIface }

def ProfileRecords.trafficLocalInput (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficPeerEntered with datapathStage := .localInput }

def ProfileRecords.trafficDelivered (records : ProfileRecords) : MultiProtocolForwarding.TunnelForwardingState :=
  { records.trafficLocalInput with datapathStage := .delivered }

lemma profile_traffic_is_source (records : ProfileRecords) (supported : SupportedProfile records) :
    records.model.deviceDataPlane.SourceRequestAllowed records.deployment records.trafficRequest ∧
    records.model.deviceDataPlane.sourceProcessing.process records.trafficRequest =
      .emitted [records.trafficDatagram] := by
  rcases supported with rfl | rfl
  · refine ⟨⟨Or.inl ⟨trafficHeader, rfl⟩, rfl, rfl, direct.networks[0], by native_decide, rfl⟩, rfl⟩
  · refine ⟨⟨Or.inl ⟨trafficHeader, rfl⟩, rfl, rfl, routed.networks[0], by native_decide, rfl⟩, rfl⟩

set_option maxHeartbeats 800000 in
lemma profile_traffic_steps (records : ProfileRecords) (supported : SupportedProfile records) :
    (⟨records.model.deviceDataPlane.AcceptedStep⟩ : Cslib.LTS _ _).MTr records.trafficStart
      [.receive, .route, .forwardFilter, .forwardWithoutEncap, .encryptMACsec,
        .linkTransmit, .decryptMACsec, .receive, .inputFilter, .deliver] records.trafficDelivered := by
  have senderMember : records.sender ∈ records.configuration.macIfaces := by
    rcases supported with rfl | rfl <;> native_decide
  have receiverMember : records.receiver ∈ records.configuration.macIfaces := by
    rcases supported with rfl | rfl <;> native_decide
  have associationInstalled : records.association ∈ records.receiver.receiveAssociations := by
    rcases supported with rfl | rfl <;> native_decide
  have firstVisible : records.configuration.visibleHeader records.trafficStart.frame =
      some (PacketSource.sourceHeader records.trafficRequest trafficHeader [7, 8]) := by
    rcases supported with rfl | rfl <;> rfl
  have nextVisible : records.configuration.visibleHeader records.trafficRouted.frame =
      some { PacketSource.sourceHeader records.trafficRequest trafficHeader [7, 8] with hopLimit := 63 } := by
    rcases supported with rfl | rfl <;> rfl
  have peerVisible : records.configuration.visibleHeader records.trafficDecrypted.frame =
      some { PacketSource.sourceHeader records.trafficRequest trafficHeader [7, 8] with hopLimit := 63 } := by
    rcases supported with rfl | rfl <;> rfl
  have receiveStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficStart .receive records.trafficEntered :=
    .receive rfl firstVisible "new"
  have routeStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficEntered .route records.trafficRouted := by
    apply MultiProtocolForwarding.TunnelForwardingStep.route (s := records.trafficEntered) records.trafficRoute rfl firstVisible
    · rcases supported with rfl | rfl <;>
        unfold DataPlaneForwarding.SelectedFibRoute DataPlaneForwarding.FibRoute.matches <;> native_decide
    · rfl
  have filterStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficRouted .forwardFilter records.trafficFiltered := by
    apply MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl nextVisible
    rcases supported with rfl | rfl <;> rfl
  have readyStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficFiltered .forwardWithoutEncap records.trafficReady :=
    .forwardWithoutEncap rfl nextVisible rfl
  have encryptStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficReady .encryptMACsec records.trafficEncrypted := by
    apply MultiProtocolForwarding.TunnelForwardingStep.encryptMACsec records.sender records.association senderMember rfl rfl
    rcases supported with rfl | rfl <;> exact ⟨rfl, rfl⟩
  have linkStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficEncrypted .linkTransmit records.trafficReceived := by
    apply MultiProtocolForwarding.TunnelForwardingStep.linkTransmit records.receiver.physicalIface rfl
    change (_, _) ∈ records.links
    rcases supported with rfl | rfl <;> native_decide
  have decryptStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficReceived .decryptMACsec records.trafficDecrypted :=
    .decryptMACsec records.receiver records.association records.association _ receiverMember rfl rfl rfl
      associationInstalled ⟨rfl, rfl⟩
  have peerStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficDecrypted .receive records.trafficPeerEntered :=
    .receive rfl peerVisible "new"
  have inputStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficPeerEntered .inputFilter records.trafficLocalInput := by
    apply MultiProtocolForwarding.TunnelForwardingStep.inputFilter (s := records.trafficPeerEntered) rfl peerVisible
    · rcases supported with rfl | rfl
      · exact ⟨direct.interfaces[2], by native_decide, rfl, Or.inl rfl⟩
      · exact ⟨routed.interfaces[3], by native_decide, rfl, Or.inl rfl⟩
    · rcases supported with rfl | rfl <;> rfl
  have deliveredStep : MultiProtocolForwarding.TunnelForwardingStep records.configuration records.trafficLocalInput .deliver records.trafficDelivered := by
    apply MultiProtocolForwarding.TunnelForwardingStep.deliver 1 rfl
    · rfl
    · rcases supported with rfl | rfl <;> rfl
  have linkAdmission : ∀ iface, (iface = records.sender.physicalIface ∨ iface = records.receiver.physicalIface) →
      ∀ outbound, records.configuration.LinkAdmitted iface outbound records.trafficEncrypted.frame := by
    intro iface member outbound
    refine ⟨(records.macFrames.headD (records.association, ⟨⟨0, 0, 0, []⟩, [], []⟩)).2, ?_, ?_, ?_⟩
    · rcases supported with rfl | rfl <;> rfl
    · change LinkAdmission.EthernetFrame.DescribesBody _ (.macsec records.association _) ∧ _
      constructor
      · rcases supported with rfl | rfl <;> dsimp only [LinkAdmission.EthernetFrame.DescribesBody] <;> native_decide
      · intro header impossible
        cases impossible
    · rcases member with rfl | rfl <;> rcases supported with rfl | rfl
      all_goals
        refine ⟨⟨⟨[], .allow⟩, ⟨[], .allow⟩⟩, rfl, ?_⟩
        cases outbound <;> rfl
  have decryptKeys : MACsecKeyMaterialMatches records.model.deviceDataPlane.macsecKeyMaterial
      records.association records.association := by
    exact ⟨List.replicate 16 (UInt8.ofNat records.association.keyGeneration), Or.inl (by simp), rfl, rfl⟩
  have plainDeliver : records.configuration.LinkStepAdmitted records.trafficLocalInput .deliver
      records.trafficDelivered := by
    have visible : records.trafficLocalInput.frame.visibleHeader =
        some { PacketSource.sourceHeader records.trafficRequest trafficHeader [7, 8] with hopLimit := 63 } := by
      rcases supported with rfl | rfl <;> rfl
    simp [TunnelForwardingModel.LinkStepAdmitted, visible]
  refine .stepL ⟨receiveStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨routeStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], ?_, by simp⟩ ?_
  · intro action stage header visible enabled
    have same : header = PacketSource.sourceHeader records.trafficRequest trafficHeader [7, 8] :=
      Option.some.inj (visible.symm.trans firstVisible)
    subst header
    change 1 < 64
    native_decide
  refine .stepL ⟨filterStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨readyStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨encryptStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨linkStep, by simp, by simp, ?_, by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  · refine ⟨fun _ => ⟨fun _ => linkAdmission _ (Or.inl rfl) _, fun _ => linkAdmission _ (Or.inr rfl) _, fun _ => rfl⟩, by simp, by simp, by simp⟩
  refine .stepL ⟨decryptStep, ?_, by simp, ?_, by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  · intro _
    exact ⟨records.receiver, receiverMember, records.association, associationInstalled,
      records.association, records.trafficReady.frame.body, rfl, rfl, rfl, rfl, ⟨rfl, rfl⟩, decryptKeys⟩
  · exact ⟨by simp, fun _ => linkAdmission _ (Or.inr rfl) _, by simp, by simp⟩
  refine .stepL ⟨peerStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  refine .stepL ⟨inputStep, by simp, by simp, by simp [TunnelForwardingModel.LinkStepAdmitted], by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ ?_
  exact .stepL ⟨deliveredStep, by simp, by simp, plainDeliver, by simp [TunnelForwardingModel.HeaderStepAdmitted], by simp⟩ .refl

set_option maxHeartbeats 800000 in
theorem profile_nonempty_payload_is_delivered (records : ProfileRecords) (supported : SupportedProfile records) :
    ∃ start actions finish, records.model.initial start ∧
      records.model.ForwardsAlongTrace start actions finish ∧
      (records.model.deviceDataPlane.state finish).datapathStage = .delivered ∧
      (records.model.deviceDataPlane.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (records.model.deviceDataPlane.state finish).frame.body = records.trafficDatagram.body := by
  have covered := profile_deployment_is_covered records supported
  have source := profile_traffic_is_source records supported
  obtain ⟨_, start, initialized, projection, _⟩ :=
    covered.2.2.2.1.2.1 records.trafficRequest [records.trafficDatagram] records.trafficDatagram
      source.1 source.2 (by simp)
  obtain ⟨actions, finish, trace, final⟩ := device_trace_has_model_trace records.model covered.2.2.1
    (profile_traffic_steps records supported) projection
  exact ⟨start, actions, finish, initialized, trace, final ▸ rfl, final ▸ rfl, final ▸ rfl⟩

end TDN.Deployments.MacsecProtection
